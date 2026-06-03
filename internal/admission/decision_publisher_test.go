package admission

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/audit"
)

// withTokenSource is a test-only Option that installs an explicit token source,
// letting tests inject a cached file reader with a short TTL (the rotation test
// seam) without waiting on the production 60s tokenFileCacheTTL.
func withTokenSource(src func() (string, error)) Option {
	return func(o *publisherOptions) {
		o.tokenSource = src
	}
}

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
	p := NewDecisionPublisher(srv.URL, "tok", zap.NewNop(), m, WithBufSize(1))
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

// captureAuthServer returns an httptest.Server that records the Authorization
// header of each received request onto the returned channel and replies 200.
func captureAuthServer(t *testing.T, got chan<- string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case got <- r.Header.Get("Authorization"):
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
}

// TestDecisionPublisher_TokenFile_PresentsFileContents writes a token file,
// installs WithTokenFile, and asserts the sent Authorization: Bearer matches the
// file contents (trimmed).
func TestDecisionPublisher_TokenFile_PresentsFileContents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(path, []byte("projected-token-v1\n"), 0o600))

	gotAuth := make(chan string, 4)
	srv := captureAuthServer(t, gotAuth)
	defer srv.Close()

	p := NewDecisionPublisher(srv.URL, "", zap.NewNop(), &fakePublisherMetrics{}, WithTokenFile(path))
	defer p.Stop()

	p.Publish(sampleEvent())

	select {
	case auth := <-gotAuth:
		assert.Equal(t, "Bearer projected-token-v1", auth, "trailing newline must be trimmed")
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for request with file-sourced bearer")
	}
}

// TestDecisionPublisher_TokenFile_PicksUpRotation rotates the file contents and
// asserts the next send after the cache TTL picks up the new value. Uses an
// injected cached reader with a short TTL (the production 60s would make the
// test slow).
func TestDecisionPublisher_TokenFile_PicksUpRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(path, []byte("token-old"), 0o600))

	gotAuth := make(chan string, 4)
	srv := captureAuthServer(t, gotAuth)
	defer srv.Close()

	// 20ms TTL via the same cached reader the production WithTokenFile uses.
	src := newCachedTokenFileReader(path, 20*time.Millisecond)
	p := NewDecisionPublisher(srv.URL, "", zap.NewNop(), &fakePublisherMetrics{}, withTokenSource(src))
	defer p.Stop()

	p.Publish(sampleEvent())
	select {
	case auth := <-gotAuth:
		require.Equal(t, "Bearer token-old", auth)
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for first send")
	}

	// Rotate the file and wait past the cache TTL so the next read re-reads.
	require.NoError(t, os.WriteFile(path, []byte("token-new"), 0o600))
	time.Sleep(40 * time.Millisecond)

	p.Publish(sampleEvent())
	select {
	case auth := <-gotAuth:
		assert.Equal(t, "Bearer token-new", auth, "after the cache TTL the rotated token must be presented")
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for second send")
	}
}

// TestDecisionPublisher_TokenFile_MissingAtConstructionNonFatal proves a
// missing token file at construction does not panic/fatal: the publisher is
// still enabled (a tokenSource is configured) and construction returns normally.
// Sends are skipped while the file is absent AND the dropped counter is
// incremented (FIX 8) so persistent token-file unavailability is visible in
// Prometheus.
func TestDecisionPublisher_TokenFile_MissingAtConstructionNonFatal(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist-yet")

	var calls atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	m := &fakePublisherMetrics{}
	p := NewDecisionPublisher(srv.URL, "", zap.NewNop(), m, WithTokenFile(path))
	defer p.Stop()

	// Publish while the file is missing: the send is skipped (no HTTP call) and
	// the dropped counter is incremented.
	p.Publish(sampleEvent())
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int64(0), calls.Load(), "missing token file must skip the send, not POST an empty bearer")
	assert.Equal(t, int64(1), m.dropped.Load(), "a missing token file must increment the dropped counter so Prometheus alerts fire")
}

// TestDecisionPublisher_TokenSource_EmptyThenValid_SecondSendDropped proves
// (FIX 9b) that when a token source returns ("", nil) on the second call the
// publish is skipped (zero additional POSTs) and the dropped counter ticks.
func TestDecisionPublisher_TokenSource_EmptyThenValid_SecondSendDropped(t *testing.T) {
	var callCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	callN := 0
	src := func() (string, error) {
		callN++
		if callN == 1 {
			return "valid-token", nil
		}
		return "", nil // empty on second call — simulates token briefly absent
	}

	m := &fakePublisherMetrics{}
	p := NewDecisionPublisher(srv.URL, "", zap.NewNop(), m, withTokenSource(src))
	defer p.Stop()

	// First publish: valid token → one POST.
	p.Publish(sampleEvent())
	require.Eventually(t, func() bool { return callCount.Load() == 1 }, 3*time.Second, 5*time.Millisecond,
		"first publish should reach the server")

	// Second publish: empty token → zero additional POSTs, dropped counter +1.
	p.Publish(sampleEvent())
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, int64(1), callCount.Load(), "empty token on second send must produce zero additional POSTs")
	assert.Equal(t, int64(1), m.dropped.Load(), "empty token source must increment the dropped counter")
}

// TestDecisionPublisher_TokenFile_PrecedenceOverStatic proves WithTokenFile
// takes precedence over the static token passed to NewDecisionPublisher.
func TestDecisionPublisher_TokenFile_PrecedenceOverStatic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(path, []byte("file-token"), 0o600))

	gotAuth := make(chan string, 4)
	srv := captureAuthServer(t, gotAuth)
	defer srv.Close()

	p := NewDecisionPublisher(srv.URL, "static-token", zap.NewNop(), &fakePublisherMetrics{}, WithTokenFile(path))
	defer p.Stop()

	p.Publish(sampleEvent())
	select {
	case auth := <-gotAuth:
		assert.Equal(t, "Bearer file-token", auth, "the file token source must take precedence over the static token")
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for request")
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
