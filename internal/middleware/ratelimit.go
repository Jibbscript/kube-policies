// Package middleware provides shared gin middleware for the kube-policies HTTP
// servers. The rate-limiting / DoS-protection middleware (NET-WU-14/15,
// RES-WU-17) is mounted on all three gin routers (admission webhook,
// policy-manager API, dashboard) to protect them from request floods and
// oversized payloads.
//
// Design — how the three rejection modes are distinguished:
//
//   - 429 "rate":       the global token-bucket limiter (golang.org/x/time/rate)
//     refused a token (sustained req/s + burst exceeded).
//   - 429 "concurrency": the max-in-flight semaphore was full (NON-blocking
//     acquire — the request is rejected immediately rather
//     than queued, so a slow upstream cannot build an
//     unbounded backlog).
//   - 413 "body_too_large": http.MaxBytesReader tripped because the request body
//     exceeded the configured cap. This is enforced lazily by
//     the handler reading the body, so RateLimit wraps the body
//     reader and the handler surfaces the 413 — but RateLimit
//     ALSO eagerly rejects on a Content-Length header that
//     already exceeds the cap, so an oversized declared body is
//     refused before it is read.
//
// State is per-instance: callers construct one *RateLimiter per server and
// inject it. There are no package-level globals, so two servers in the same
// process (or two test engines) get independent limiters.
package middleware

import (
	"net/http"
	"sync/atomic"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// Reason label values recorded on the kube_policies_http_rate_limited_total
// metric. Pinned as constants so the middleware and its tests cannot drift.
const (
	ReasonRate           = "rate"
	ReasonConcurrency    = "concurrency"
	ReasonBodyTooLarge   = "body_too_large"
	ReasonStreamCapacity = "stream_capacity"
)

// Metrics is the small interface the middleware needs to record rejections. It
// mirrors the publisherMetrics pattern in internal/admission/decision_publisher.go
// so tests can pass a fake without importing the full metrics.Collector.
// *metrics.Collector satisfies it via IncRateLimited.
type Metrics interface {
	IncRateLimited(handler, reason string)
}

// Config configures the rate-limiting / DoS-protection middleware. The zero
// value (Enabled=false) yields a pass-through no-op. A non-positive value for
// any individual limit disables that particular protection while leaving the
// others active.
type Config struct {
	// RequestsPerSecond is the token-bucket refill rate. <= 0 disables the rate
	// limiter.
	RequestsPerSecond float64
	// Burst is the token-bucket depth. <= 0 disables the rate limiter.
	Burst int
	// MaxConcurrent caps in-flight requests. <= 0 disables the concurrency cap.
	MaxConcurrent int
	// MaxBodyBytes caps request body size; oversized requests get 413. <= 0
	// disables the body cap.
	MaxBodyBytes int64
	// Enabled toggles the whole middleware. When false, RequestMiddleware returns
	// a no-op pass-through.
	Enabled bool
}

// RateLimiter holds the per-server limiter state. Construct with New and inject
// the resulting gin middleware via RequestMiddleware. Safe for concurrent use:
// the token bucket is internally synchronized and the semaphore is a channel.
type RateLimiter struct {
	cfg     Config
	metrics Metrics
	// limiter is nil when the rate limiter is disabled (rps/burst <= 0).
	limiter *rate.Limiter
	// sem is a buffered channel used as a counting semaphore. nil when the
	// concurrency cap is disabled (MaxConcurrent <= 0). A non-blocking send
	// acquires a slot; a receive releases it.
	sem chan struct{}
}

// New constructs a RateLimiter from cfg. A nil metrics is tolerated (rejections
// are then not counted). When cfg.Enabled is false the returned limiter's
// RequestMiddleware is a pass-through.
func New(cfg Config, m Metrics) *RateLimiter {
	rl := &RateLimiter{cfg: cfg, metrics: m}
	if !cfg.Enabled {
		return rl
	}
	if cfg.RequestsPerSecond > 0 && cfg.Burst > 0 {
		rl.limiter = rate.NewLimiter(rate.Limit(cfg.RequestsPerSecond), cfg.Burst)
	}
	if cfg.MaxConcurrent > 0 {
		rl.sem = make(chan struct{}, cfg.MaxConcurrent)
	}
	return rl
}

// handlerLabel returns the metric "handler" label for a request: the matched
// gin route (e.g. "/validate"), falling back to the raw path so an unmatched
// request is still attributed. Using FullPath keeps cardinality bounded (the
// route template, not the concrete URL with path params).
func handlerLabel(c *gin.Context) string {
	if p := c.FullPath(); p != "" {
		return p
	}
	return c.Request.URL.Path
}

func (rl *RateLimiter) inc(c *gin.Context, reason string) {
	if rl.metrics != nil {
		rl.metrics.IncRateLimited(handlerLabel(c), reason)
	}
}

// RequestMiddleware returns the gin middleware enforcing the body cap, the
// global rate limit, and the in-flight concurrency cap, in that order. It is a
// pass-through when the limiter is disabled. Mount it on the routes you want
// protected; do NOT mount it on health/readiness probes (those run constantly
// and must never be throttled).
//
// Order rationale: the body cap is applied first (cheapest, and an oversized
// body should be rejected regardless of load); then the rate limit (reject a
// flood before reserving a concurrency slot); then the concurrency cap (the slot
// is held for the duration of the handler and released via defer).
func (rl *RateLimiter) RequestMiddleware() gin.HandlerFunc {
	if !rl.cfg.Enabled {
		return func(c *gin.Context) { c.Next() }
	}
	return func(c *gin.Context) {
		// 1) Body cap (413). Reject eagerly when the declared Content-Length
		//    already exceeds the cap, and wrap the body so a streamed/chunked
		//    request that lies about its length still trips when the handler
		//    reads past the cap (http.MaxBytesReader returns an error on Read).
		if rl.cfg.MaxBodyBytes > 0 {
			if c.Request.ContentLength > rl.cfg.MaxBodyBytes {
				rl.inc(c, ReasonBodyTooLarge)
				c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
					"error": "request body too large",
				})
				return
			}
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, rl.cfg.MaxBodyBytes)
		}

		// 2) Global rate limit (429). Non-blocking Allow(): a refused token is
		//    rejected immediately rather than waiting, so the apiserver's
		//    admission timeout is never consumed by queueing inside the webhook.
		if rl.limiter != nil && !rl.limiter.Allow() {
			rl.inc(c, ReasonRate)
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "rate limit exceeded",
			})
			return
		}

		// 3) In-flight concurrency cap (429). Non-blocking acquire: if the
		//    semaphore is full the request is rejected rather than queued. The
		//    slot is released when the handler chain returns.
		if rl.sem != nil {
			select {
			case rl.sem <- struct{}{}:
				defer func() { <-rl.sem }()
			default:
				rl.inc(c, ReasonConcurrency)
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
					"error": "too many concurrent requests",
				})
				return
			}
		}

		c.Next()
	}
}

// StreamGate is a dedicated concurrent-connection gate for long-lived SSE
// stream handlers (NET-WU-15). SSE connections are held open for the lifetime of
// the browser/subscriber, so they must NOT count against the general
// RateLimiter.MaxConcurrent budget — a handful of dashboards would otherwise
// starve the request limiter. The gate admits up to max concurrent streams and
// rejects the next one with 429; the slot is released when the connection
// closes (the handler returns).
//
// Implemented with an atomic counter (not a channel) so the cap can be 0
// (disabled) without allocating, and so the active count is observable for
// tests. A non-positive max disables the gate (no cap).
type StreamGate struct {
	max     int64
	active  atomic.Int64
	metrics Metrics
	handler string
}

// NewStreamGate constructs a StreamGate capping concurrent streams at max for
// the named handler (used as the metric "handler" label). A non-positive max
// disables the cap. A nil metrics is tolerated.
func NewStreamGate(max int, handler string, m Metrics) *StreamGate {
	return &StreamGate{max: int64(max), metrics: m, handler: handler}
}

// Middleware returns a gin middleware that acquires a stream slot before
// c.Next() and releases it after the handler returns. When the cap is reached it
// aborts with 429 and records a "stream_capacity" rejection. It is a
// pass-through when the gate is disabled (max <= 0).
func (g *StreamGate) Middleware() gin.HandlerFunc {
	if g == nil || g.max <= 0 {
		return func(c *gin.Context) { c.Next() }
	}
	return func(c *gin.Context) {
		// Reserve a slot optimistically, then bounds-check. If we exceeded the
		// cap, release immediately and reject. This compare-and-release pattern
		// avoids a lock while staying race-free under -race.
		if g.active.Add(1) > g.max {
			g.active.Add(-1)
			if g.metrics != nil {
				g.metrics.IncRateLimited(g.handler, ReasonStreamCapacity)
			}
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error": "stream connection limit reached",
			})
			return
		}
		defer g.active.Add(-1)
		c.Next()
	}
}

// Active reports the current number of in-flight stream connections. Exposed for
// tests and operational introspection.
func (g *StreamGate) Active() int64 {
	if g == nil {
		return 0
	}
	return g.active.Load()
}
