package admission

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/audit"
)

const defaultPublisherBufSize = 256

// tokenFileCacheTTL bounds how long a token read from a file (WithTokenFile) is
// reused before the file is re-read. The projected ServiceAccount token mounted
// by the kubelet (IAM-WU-11) is rotated well before its short TTL elapses, so a
// 60s cache keeps the presented token fresh while avoiding a disk read on every
// publish.
const tokenFileCacheTTL = 60 * time.Second

// publisherMetrics is a small interface so tests can pass a fake without
// importing the full metrics.Collector.
type publisherMetrics interface {
	IncWebhookDecisionPublishDropped()
}

// DecisionPublisher forwards admission-decision events to the policy-manager's
// internal ingest endpoint over HTTP. It is fire-and-forget: events that cannot
// be delivered due to upstream errors are logged and discarded. Publish never
// blocks the calling goroutine.
type DecisionPublisher struct {
	url   string
	token string
	// tokenSource, when non-nil, resolves the bearer per-send (IAM-WU-11): it
	// returns the current projected ServiceAccount token read from a mounted
	// file. It takes precedence over the static token. A non-nil tokenSource
	// also marks the publisher as enabled regardless of the static token.
	tokenSource func() (string, error)
	client      *http.Client
	buf         chan audit.PublicEvent
	logger      *zap.Logger
	metrics     publisherMetrics
	wg          sync.WaitGroup
	once        sync.Once
}

// Option configures a DecisionPublisher.
type Option func(*publisherOptions)

type publisherOptions struct {
	bufSize     int
	tlsConfig   *tls.Config
	tokenSource func() (string, error)
}

// WithBufSize overrides the internal channel capacity (default 256).
func WithBufSize(n int) Option {
	return func(o *publisherOptions) {
		if n > 0 {
			o.bufSize = n
		}
	}
}

// WithTLSConfig makes the publisher reach the policy-manager over verified TLS
// (CRY-WU-06). The config's RootCAs must trust the policy-manager serving cert;
// InsecureSkipVerify must never be set. A nil config leaves the default
// transport (system roots), so an externally-managed PKI still works.
func WithTLSConfig(c *tls.Config) Option {
	return func(o *publisherOptions) {
		o.tlsConfig = c
	}
}

// WithTokenFile makes the publisher present a rotating bearer token read from
// path (IAM-WU-11) instead of a static string. path is the in-pod location of a
// projected ServiceAccount token (audience-bound, short-TTL) atomically swapped
// by the kubelet. It takes precedence over the static token passed to
// NewDecisionPublisher and marks the publisher as enabled.
//
// The reader caches the last value for tokenFileCacheTTL (60s) and re-reads the
// path (NOT a cached fd or resolved symlink — the kubelet atomic-swaps ..data,
// so following the path string is required to observe rotations) on the next
// read after the TTL elapses. strings.TrimSpace strips the trailing newline some
// token files carry. A transient read error (e.g. ENOENT during a swap) is
// non-fatal: the last-good value is returned, or "" if none has been read yet.
func WithTokenFile(path string) Option {
	return func(o *publisherOptions) {
		o.tokenSource = newCachedTokenFileReader(path, tokenFileCacheTTL)
	}
}

// newCachedTokenFileReader returns a token source that reads path, caching the
// last value for ttl. Exposed via a constructor (rather than inlined in
// WithTokenFile) so ttl is injectable for tests. See WithTokenFile for the
// rotation/error semantics.
func newCachedTokenFileReader(path string, ttl time.Duration) func() (string, error) {
	var (
		mu       sync.RWMutex
		last     string
		lastRead time.Time
	)
	return func() (string, error) {
		mu.RLock()
		if !lastRead.IsZero() && time.Since(lastRead) <= ttl {
			v := last
			mu.RUnlock()
			return v, nil
		}
		mu.RUnlock()

		mu.Lock()
		defer mu.Unlock()
		// Re-check under the write lock: another goroutine may have refreshed.
		if !lastRead.IsZero() && time.Since(lastRead) <= ttl {
			return last, nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			// Transient (e.g. ENOENT mid-swap): return last-good (or "") and do
			// not advance lastRead so the next call retries promptly.
			return last, nil
		}
		last = strings.TrimSpace(string(b))
		lastRead = time.Now()
		return last, nil
	}
}

// NewDecisionPublisher creates a DecisionPublisher that POSTs events to url
// with the given bearer token.
//
// The publisher is ENABLED when either a non-empty static token is supplied OR a
// token source is installed via WithTokenFile (IAM-WU-11); the file source takes
// precedence over the static token. When neither is configured the publisher is
// disabled: a structured warning is logged at construction time and Publish is
// always a no-op. A nil metrics argument is safe. Use WithBufSize /
// WithTLSConfig / WithTokenFile to customize.
func NewDecisionPublisher(url, token string, log *zap.Logger, m publisherMetrics, opts ...Option) *DecisionPublisher {
	if log == nil {
		log = zap.NewNop()
	}
	o := publisherOptions{bufSize: defaultPublisherBufSize}
	for _, opt := range opts {
		opt(&o)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	if o.tlsConfig != nil {
		client.Transport = &http.Transport{TLSClientConfig: o.tlsConfig}
	}

	p := &DecisionPublisher{
		url:         url,
		token:       token,
		tokenSource: o.tokenSource,
		client:      client,
		buf:         make(chan audit.PublicEvent, o.bufSize),
		logger:      log,
		metrics:     m,
	}

	if !p.enabled() {
		log.Warn("kube-policies.webhook.decision_publisher.disabled",
			zap.String("reason", "no token configured (POLICY_MANAGER_INTERNAL_TOKEN empty and no --policy-manager-token-path); decision publishing is a no-op"),
		)
		// Dispatcher goroutine is NOT started; Publish will return immediately.
		return p
	}

	p.wg.Add(1)
	go p.dispatch()
	return p
}

// enabled reports whether the publisher will deliver events: true when a token
// source (WithTokenFile) is installed OR a non-empty static token is set. A
// configured tokenSource counts as enabled even before its first successful read
// — construction is fire-and-forget and the file may briefly lag pod start.
func (p *DecisionPublisher) enabled() bool {
	return p.tokenSource != nil || p.token != ""
}

// Publish enqueues ev for delivery to the policy-manager. It never blocks: if
// the internal buffer is full the event is dropped and the dropped counter is
// incremented. It is a no-op when the publisher is disabled (empty token).
func (p *DecisionPublisher) Publish(ev audit.PublicEvent) {
	if !p.enabled() {
		return
	}
	select {
	case p.buf <- ev:
	default:
		if p.metrics != nil {
			p.metrics.IncWebhookDecisionPublishDropped()
		}
		p.logger.Warn("kube-policies.webhook.decision_publisher.dropped",
			zap.String("decision", ev.Decision),
			zap.String("kind", ev.Kind),
		)
	}
}

// Stop closes the internal buffer so the dispatcher drains any in-flight events
// and exits. It blocks until the dispatcher has finished. Safe to call multiple
// times.
func (p *DecisionPublisher) Stop() {
	p.once.Do(func() {
		close(p.buf)
	})
	p.wg.Wait()
}

// dispatch is the single background goroutine that reads from buf and POSTs
// events to the policy-manager. It exits when buf is closed.
func (p *DecisionPublisher) dispatch() {
	defer p.wg.Done()
	for ev := range p.buf {
		if err := p.post(ev); err != nil {
			// A tokenSourceEmptyErr means the projected token file is
			// transiently absent (FIX 8). Increment the dropped counter so
			// persistent unavailability is visible in Prometheus; log at warn
			// without the token value so operators can detect misconfiguration.
			var tsEmpty tokenSourceEmptyErr
			if errors.As(err, &tsEmpty) {
				if p.metrics != nil {
					p.metrics.IncWebhookDecisionPublishDropped()
				}
				p.logger.Warn("kube-policies.webhook.decision_publisher.token_unavailable",
					zap.String("decision", ev.Decision),
					zap.String("kind", ev.Kind),
				)
				continue
			}
			p.logger.Warn("kube-policies.webhook.decision_publisher.post_failed",
				zap.Error(err),
				zap.String("decision", ev.Decision),
				zap.String("kind", ev.Kind),
			)
		}
	}
}

// post marshals ev to JSON and POSTs it to p.url with a Bearer token header.
// Returns an error on marshal failure, HTTP transport errors, or non-2xx status.
// The per-request context bounds the dial+send to the client timeout so a hung
// upstream cannot park the dispatcher goroutine indefinitely.
// tokenSourceEmpty is a sentinel error returned by post when the configured
// token source resolves to "" (e.g. the projected token file is absent during a
// kubelet rotation). It is used by dispatch to increment the dropped counter so
// persistent token-file unavailability is visible in Prometheus.
type tokenSourceEmptyErr struct{}

func (tokenSourceEmptyErr) Error() string {
	return "token source returned empty token; event dropped until token file is available"
}

func (p *DecisionPublisher) post(ev audit.PublicEvent) error {
	// Resolve the bearer per-send (IAM-WU-11): a configured token source (the
	// projected SA token file) takes precedence over the static token. A source
	// error or an empty value causes the send to be skipped (non-fatal) rather
	// than POSTing a stale/empty credential. The token itself is never logged.
	bearer := p.token
	if p.tokenSource != nil {
		tok, srcErr := p.tokenSource()
		if srcErr != nil {
			return fmt.Errorf("resolve token: %w", srcErr)
		}
		if tok == "" {
			// Return the typed sentinel so dispatch can distinguish an
			// unavailable token file from a genuine upstream error and
			// increment the dropped counter (FIX 8 — persistent token-file
			// unavailability must be visible in Prometheus).
			return tokenSourceEmptyErr{}
		}
		bearer = tok
	}

	body, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), p.client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("http post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return nil
}
