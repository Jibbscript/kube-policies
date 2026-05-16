package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/audit"
)

// PublicEvent is the strict-whitelist DTO defined in internal/audit. The
// dashboard re-exports it here for proximity; the SPA shape is mirrored in
// web/src/lib/types.ts. Keep the JSON tags in audit/public_event.go stable —
// the SPA depends on these field names.
type PublicEvent = audit.PublicEvent

// Ring is a fixed-capacity, ring-buffered store of recent PublicEvents.
// Concurrent-safe; reads return a copy so callers can iterate without
// holding the lock.
type Ring struct {
	mu       sync.RWMutex
	items    []PublicEvent
	capacity int
	// next is the index where the next Add will write.
	next int
	// full reports whether the buffer has wrapped at least once.
	full bool
}

// NewRing constructs a Ring with the given capacity. capacity <= 0 is
// normalized to 1 to avoid pathological zero-length buffers.
func NewRing(capacity int) *Ring {
	if capacity <= 0 {
		capacity = 1
	}
	return &Ring{
		items:    make([]PublicEvent, capacity),
		capacity: capacity,
	}
}

// Add inserts ev at the next slot, overwriting the oldest entry once full.
func (r *Ring) Add(ev PublicEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items[r.next] = ev
	r.next = (r.next + 1) % r.capacity
	if r.next == 0 {
		r.full = true
	}
}

// Recent returns up to `limit` most-recent events, newest first.
func (r *Ring) Recent(limit int) []PublicEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var size int
	if r.full {
		size = r.capacity
	} else {
		size = r.next
	}
	if limit < 0 || limit > size {
		limit = size
	}
	out := make([]PublicEvent, 0, limit)
	// Walk backwards from the most-recent write.
	for i := 0; i < limit; i++ {
		idx := (r.next - 1 - i + r.capacity) % r.capacity
		out = append(out, r.items[idx])
	}
	return out
}

// Len returns the current count of stored events (0..capacity).
func (r *Ring) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.full {
		return r.capacity
	}
	return r.next
}

// NewIngestHandler returns a handler for POST /api/decisions/internal.
//
// Requires Authorization: Bearer <cfg.InternalToken>. If InternalToken is
// empty (unconfigured) the endpoint is closed — it returns 401 on every
// request. This is deliberate: an empty token must not act as a wildcard.
func NewIngestHandler(cfg *Config, ring *Ring, log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		if cfg.InternalToken == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "internal token not configured",
			})
			return
		}
		auth := c.GetHeader("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(auth, prefix) || strings.TrimPrefix(auth, prefix) != cfg.InternalToken {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid bearer token",
			})
			return
		}
		var ev PublicEvent
		if err := json.NewDecoder(c.Request.Body).Decode(&ev); err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "invalid event body",
			})
			return
		}
		if ev.Decision == "" {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
				"error": "decision is required",
			})
			return
		}
		if ev.Timestamp.IsZero() {
			ev.Timestamp = time.Now().UTC()
		}
		ring.Add(ev)
		log.Debug("ingested public event",
			zap.String("decision", ev.Decision),
			zap.String("rule_id", ev.RuleID),
		)
		c.Status(http.StatusNoContent)
	}
}

// NewRecentHandler returns a handler for GET /api/decisions/recent?limit=N.
//
// The response shape is `{"events":[...], "degraded": bool}`. degraded
// is true when the ring is empty — a signal to the SPA's ModeBanner that
// the live publisher is not yet wired (M1 reality).
func NewRecentHandler(ring *Ring, log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		limit := 20
		if s := c.Query("limit"); s != "" {
			if n, err := strconv.Atoi(s); err == nil {
				limit = n
			}
		}
		if limit < 1 {
			limit = 1
		}
		if limit > 100 {
			limit = 100
		}
		items := ring.Recent(limit)
		c.JSON(http.StatusOK, gin.H{
			"events":   items,
			"degraded": len(items) == 0,
		})
	}
}

// streamHub is a lightweight fan-out pub-sub for the dashboard SSE proxy.
// Drop-oldest semantics: when a subscriber's buffer is full the oldest event
// is evicted to make room for the newest. Publish never blocks the caller.
type streamHub struct {
	mu    sync.RWMutex
	subs  map[uint64]chan PublicEvent
	next  uint64
	bufSz int
	log   *zap.Logger
}

func newStreamHub(bufSize int, log *zap.Logger) *streamHub {
	if bufSize <= 0 {
		bufSize = 256
	}
	return &streamHub{
		subs:  make(map[uint64]chan PublicEvent),
		bufSz: bufSize,
		log:   log,
	}
}

// subscribe returns a receive-only channel and an idempotent cancel function.
// The channel is closed when cancel is called.
func (h *streamHub) subscribe() (<-chan PublicEvent, func()) {
	h.mu.Lock()
	id := h.next
	h.next++
	ch := make(chan PublicEvent, h.bufSz)
	h.subs[id] = ch
	h.mu.Unlock()

	cancel := func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if _, ok := h.subs[id]; ok {
			delete(h.subs, id)
			close(ch)
		}
	}
	return ch, cancel
}

// publish delivers ev to all current subscribers using drop-oldest semantics.
func (h *streamHub) publish(ev PublicEvent) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, ch := range h.subs {
		h.sendOne(ch, ev)
	}
}

func (h *streamHub) sendOne(ch chan PublicEvent, ev PublicEvent) {
	select {
	case ch <- ev:
	default:
		// Buffer full: evict oldest, then retry.
		select {
		case <-ch:
		default:
		}
		select {
		case ch <- ev:
		default:
			h.log.Warn("stream hub: subscriber buffer full, event dropped",
				zap.String("decision", ev.Decision),
			)
		}
	}
}

// streamHandler manages a single upstream SSE subscription and fans out to N
// concurrent browser SSE clients. The upstream connection is started lazily on
// the first browser connection via sync.Once.
type streamHandler struct {
	cfg  *Config
	log  *zap.Logger
	hub  *streamHub
	ctx  context.Context
	once sync.Once
}

// NewStreamHandler returns a gin.HandlerFunc that proxies the upstream
// policy-manager SSE stream (cfg.PolicyManagerStreamURL) to all connected
// browser clients.
//
// ctx is the process lifecycle context; cancel it to stop the upstream
// subscriber goroutine on shutdown. The goroutine is started lazily on the
// first browser connection.
func NewStreamHandler(ctx context.Context, cfg *Config, log *zap.Logger) gin.HandlerFunc {
	h := &streamHandler{
		cfg: cfg,
		log: log,
		hub: newStreamHub(256, log),
		ctx: ctx,
	}
	return h.serve
}

func (h *streamHandler) serve(c *gin.Context) {
	// Lazily start the upstream subscriber on the first browser connection.
	h.once.Do(func() {
		go h.runUpstream()
	})

	ch, unsub := h.hub.subscribe()
	defer unsub()

	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")
	if f, ok := c.Writer.(http.Flusher); ok {
		f.Flush()
	}

	tick := time.NewTicker(15 * time.Second)
	defer tick.Stop()

	reqCtx := c.Request.Context()

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			data, _ := json.Marshal(ev)
			fmt.Fprintf(c.Writer, "data: %s\n\n", data)
			if f, ok := c.Writer.(http.Flusher); ok {
				f.Flush()
			}
		case <-tick.C:
			fmt.Fprint(c.Writer, ": heartbeat\n\n")
			if f, ok := c.Writer.(http.Flusher); ok {
				f.Flush()
			}
		case <-reqCtx.Done():
			return
		}
	}
}

// runUpstream continuously subscribes to the upstream SSE stream and publishes
// parsed events to the hub. It reconnects with exponential backoff on error.
func (h *streamHandler) runUpstream() {
	const (
		initialBackoff = 500 * time.Millisecond
		maxBackoff     = 30 * time.Second
	)
	backoff := initialBackoff

	for {
		if h.ctx.Err() != nil {
			return
		}

		connected, err := h.fetchAndStream()

		if h.ctx.Err() != nil {
			return
		}

		if connected {
			// Successful connection that closed; reset backoff for next reconnect.
			backoff = initialBackoff
			if err != nil {
				h.log.Warn("upstream SSE stream closed with error", zap.Error(err),
					zap.Duration("retry_in", backoff))
			} else {
				h.log.Info("upstream SSE stream closed cleanly",
					zap.Duration("retry_in", backoff))
			}
		} else {
			h.log.Warn("upstream SSE connection failed", zap.Error(err),
				zap.Duration("retry_in", backoff))
		}

		select {
		case <-h.ctx.Done():
			return
		case <-time.After(backoff):
		}

		if !connected {
			backoff = min(backoff*2, maxBackoff)
		}
	}
}

// fetchAndStream dials the upstream SSE endpoint and reads events into the hub.
// Returns (true, err) when we received HTTP 200 (even if the subsequent read
// later failed).  Returns (false, err) on dial or non-200 errors.
func (h *streamHandler) fetchAndStream() (connected bool, err error) {
	req, err := http.NewRequestWithContext(h.ctx, http.MethodGet,
		h.cfg.PolicyManagerStreamURL, nil)
	if err != nil {
		return false, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "text/event-stream")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("connect: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("upstream status %d", resp.StatusCode)
	}

	h.log.Info("connected to upstream SSE",
		zap.String("url", h.cfg.PolicyManagerStreamURL))

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		const prefix = "data: "
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		payload := strings.TrimPrefix(line, prefix)
		var ev PublicEvent
		if jsonErr := json.Unmarshal([]byte(payload), &ev); jsonErr != nil {
			h.log.Warn("upstream SSE: invalid JSON payload",
				zap.String("payload", payload),
				zap.Error(jsonErr),
			)
			continue
		}
		h.hub.publish(ev)
	}
	return true, scanner.Err()
}
