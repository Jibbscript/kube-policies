package admission

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/audit"
)

// fakePublisherMetrics implements publisherMetrics for testing without importing
// the metrics package (avoids duplicate Prometheus registry registrations).
type fakePublisherMetrics struct {
	dropped atomic.Int64
}

func (f *fakePublisherMetrics) IncWebhookDecisionPublishDropped() {
	f.dropped.Add(1)
}

func sampleEvent() audit.PublicEvent {
	return audit.PublicEvent{
		Decision:  "DENY",
		Namespace: "default",
		Kind:      "Pod",
		Name:      "test-pod",
		RuleID:    "no-privileged-containers",
		PolicyID:  "security-baseline",
		Timestamp: time.Now(),
	}
}

// TestDecisionPublisher_HappyPath verifies that a published event reaches the
// upstream server with the correct Authorization header and a decodable body.
func TestDecisionPublisher_HappyPath(t *testing.T) {
	received := make(chan audit.PublicEvent, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-token" {
			t.Errorf("wrong Authorization header: %q", got)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var ev audit.PublicEvent
		if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
			t.Errorf("body decode: %v", err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		received <- ev
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := &fakePublisherMetrics{}
	p := NewDecisionPublisher(srv.URL, "test-token", zap.NewNop(), m)
	defer p.Stop()

	ev := sampleEvent()
	p.Publish(ev)

	select {
	case got := <-received:
		if got.Decision != ev.Decision {
			t.Errorf("Decision: want %q got %q", ev.Decision, got.Decision)
		}
		if got.Kind != ev.Kind {
			t.Errorf("Kind: want %q got %q", ev.Kind, got.Kind)
		}
		if got.RuleID != ev.RuleID {
			t.Errorf("RuleID: want %q got %q", ev.RuleID, got.RuleID)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for event to be delivered to upstream server")
	}
}

// TestDecisionPublisher_DropOnFullBuffer verifies that events are dropped (and
// the metrics counter incremented) when the dispatcher is busy and the buffer
// is full.
func TestDecisionPublisher_DropOnFullBuffer(t *testing.T) {
	// serverReady is signaled by the first request handler to indicate the
	// dispatcher goroutine is now blocked inside the HTTP call.
	serverReady := make(chan struct{}, 1)
	blocked := make(chan struct{}) // close to unblock the server handler

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case serverReady <- struct{}{}:
		default:
		}
		<-blocked
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	defer close(blocked)

	m := &fakePublisherMetrics{}
	// Capacity = 1 so one event sits in the buffer while the dispatcher is stuck.
	p := NewDecisionPublisher(srv.URL, "tok", zap.NewNop(), m, 1)
	defer p.Stop()

	// Prime the dispatcher: publish one event so it connects to the server and blocks.
	p.Publish(sampleEvent())

	// Wait until the dispatcher is inside the server handler.
	select {
	case <-serverReady:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout: dispatcher never reached the server")
	}

	// At this point the dispatcher is blocked and buf is empty (capacity 1).
	// Flood with 10 more events: first fills the buffer, rest must drop.
	for range 10 {
		p.Publish(sampleEvent())
	}

	if got := m.dropped.Load(); got < 9 {
		t.Errorf("want >= 9 dropped events, got %d", got)
	}
}

// TestDecisionPublisher_DisabledWhenTokenEmpty verifies that no HTTP requests
// are made when the token is empty.
func TestDecisionPublisher_DisabledWhenTokenEmpty(t *testing.T) {
	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := &fakePublisherMetrics{}
	p := NewDecisionPublisher(srv.URL, "", zap.NewNop(), m)
	defer p.Stop()

	for range 5 {
		p.Publish(sampleEvent())
	}

	// Allow any goroutine (there should be none) time to fire.
	time.Sleep(100 * time.Millisecond)

	if n := calls.Load(); n != 0 {
		t.Errorf("expected 0 requests to upstream, got %d", n)
	}
}

// TestDecisionPublisher_NeverBlocks verifies that 100 Publish calls return
// promptly even when the upstream is completely unreachable.
func TestDecisionPublisher_NeverBlocks(t *testing.T) {
	m := &fakePublisherMetrics{}
	// Port 1 is reserved and will immediately refuse connections.
	p := NewDecisionPublisher("http://127.0.0.1:1", "tok", zap.NewNop(), m)
	defer p.Stop()

	start := time.Now()
	for range 100 {
		p.Publish(sampleEvent())
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("100 Publish calls took %v; want < 100ms (must not block)", elapsed)
	}
}
