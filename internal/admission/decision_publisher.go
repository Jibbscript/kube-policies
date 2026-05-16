package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/audit"
)

const defaultPublisherBufSize = 256

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
	url     string
	token   string
	client  *http.Client
	buf     chan audit.PublicEvent
	logger  *zap.Logger
	metrics publisherMetrics
	wg      sync.WaitGroup
	once    sync.Once
}

// NewDecisionPublisher creates a DecisionPublisher that POSTs events to url
// with the given bearer token.
//
// If token is empty the publisher is disabled: a structured warning is logged
// at construction time and Publish is always a no-op. Pass bufSize > 0 to
// override the default channel capacity of 256. A nil metrics argument is safe.
func NewDecisionPublisher(url, token string, log *zap.Logger, m publisherMetrics, bufSize ...int) *DecisionPublisher {
	if log == nil {
		log = zap.NewNop()
	}
	sz := defaultPublisherBufSize
	if len(bufSize) > 0 && bufSize[0] > 0 {
		sz = bufSize[0]
	}

	p := &DecisionPublisher{
		url:     url,
		token:   token,
		client:  &http.Client{Timeout: 5 * time.Second},
		buf:     make(chan audit.PublicEvent, sz),
		logger:  log,
		metrics: m,
	}

	if token == "" {
		log.Warn("kube-policies.webhook.decision_publisher.disabled",
			zap.String("reason", "POLICY_MANAGER_INTERNAL_TOKEN is empty; decision publishing is a no-op"),
		)
		// Dispatcher goroutine is NOT started; Publish will return immediately.
		return p
	}

	p.wg.Add(1)
	go p.dispatch()
	return p
}

// Publish enqueues ev for delivery to the policy-manager. It never blocks: if
// the internal buffer is full the event is dropped and the dropped counter is
// incremented. It is a no-op when the publisher is disabled (empty token).
func (p *DecisionPublisher) Publish(ev audit.PublicEvent) {
	if p.token == "" {
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
func (p *DecisionPublisher) post(ev audit.PublicEvent) error {
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
	req.Header.Set("Authorization", "Bearer "+p.token)

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
