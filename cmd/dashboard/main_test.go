package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func newTestRouter(t *testing.T, cfg *Config) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(cspMiddleware(cfg.CSPUnsafeInlineStyle))
	r.GET("/healthz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "healthy"}) })
	r.GET("/readyz", func(c *gin.Context) { c.JSON(http.StatusOK, gin.H{"status": "ready"}) })
	ring := NewRing(8)
	log := zap.NewNop()
	r.GET("/api/decisions/recent", NewRecentHandler(ring, log))
	r.POST("/api/decisions/internal", NewIngestHandler(cfg, ring, log))
	return r
}

func TestHealthzAndReadyz(t *testing.T) {
	r := newTestRouter(t, &Config{})
	for _, path := range []string{"/healthz", "/readyz"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s = %d, want 200", path, w.Code)
		}
	}
}

func TestCSPHeader_DefaultExcludesUnsafeInline(t *testing.T) {
	r := newTestRouter(t, &Config{CSPUnsafeInlineStyle: false})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	csp := w.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("missing Content-Security-Policy header")
	}
	if strings.Contains(csp, "'unsafe-inline'") {
		t.Errorf("default CSP must not contain 'unsafe-inline'; got %q", csp)
	}
	if !strings.Contains(csp, "default-src 'self'") {
		t.Errorf("CSP missing default-src 'self'; got %q", csp)
	}
	if !strings.Contains(csp, "object-src 'none'") {
		t.Errorf("CSP missing object-src 'none'; got %q", csp)
	}
	if !strings.Contains(csp, "style-src 'self'") {
		t.Errorf("CSP missing style-src 'self'; got %q", csp)
	}
}

func TestCSPHeader_UnsafeInlineWhenConfigured(t *testing.T) {
	r := newTestRouter(t, &Config{CSPUnsafeInlineStyle: true})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "style-src 'self' 'unsafe-inline'") {
		t.Errorf("expected style-src to include 'unsafe-inline'; got %q", csp)
	}
}

func TestIngestHandler_UnconfiguredTokenReturns401(t *testing.T) {
	r := newTestRouter(t, &Config{InternalToken: ""})
	req := httptest.NewRequest(http.MethodPost, "/api/decisions/internal",
		strings.NewReader(`{"decision":"DENY","kind":"Pod","rule_id":"x","policy_id":"y"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (unconfigured token must reject)", w.Code)
	}
}

func TestIngestHandler_WrongTokenReturns401(t *testing.T) {
	r := newTestRouter(t, &Config{InternalToken: "secret-abc"})
	req := httptest.NewRequest(http.MethodPost, "/api/decisions/internal",
		strings.NewReader(`{"decision":"DENY","kind":"Pod"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}
}

func TestIngestThenRecent_RoundTrip(t *testing.T) {
	cfg := &Config{InternalToken: "secret-abc"}
	r := newTestRouter(t, cfg)

	body := `{"decision":"DENY","namespace":"default","kind":"Pod","name":"my-pod","rule_id":"no-privileged-containers","policy_id":"security-baseline"}`
	req := httptest.NewRequest(http.MethodPost, "/api/decisions/internal", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-abc")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("ingest status = %d, want 204; body=%s", w.Code, w.Body.String())
	}

	req = httptest.NewRequest(http.MethodGet, "/api/decisions/recent?limit=5", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("recent status = %d, want 200", w.Code)
	}
	got := w.Body.String()
	if !strings.Contains(got, `"events":`) {
		t.Errorf("recent body must use the events envelope; got %s", got)
	}
	if !strings.Contains(got, `"decision":"DENY"`) {
		t.Errorf("recent body missing the ingested event; got %s", got)
	}
	if !strings.Contains(got, `"name":"my-pod"`) {
		t.Errorf("recent body must preserve the upstream Name field; got %s", got)
	}
	if strings.Contains(got, `"degraded":true`) {
		t.Errorf("ring has events; degraded must be false; got %s", got)
	}
}

func TestRecentHandler_EmptyRingReportsDegraded(t *testing.T) {
	r := newTestRouter(t, &Config{})
	req := httptest.NewRequest(http.MethodGet, "/api/decisions/recent?limit=10", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"degraded":true`) {
		t.Errorf("empty ring must report degraded:true; got %s", w.Body.String())
	}
}

func TestProxy_VerbGate_RejectsWritesWhenDisabled(t *testing.T) {
	cfg := &Config{PolicyManagerURL: "http://upstream.invalid", AllowWrites: false}
	proxy, err := NewProxyHandler(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewProxyHandler: %v", err)
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		r.Handle(m, "/api/v1/*proxyPath", proxy)
	}

	for _, tc := range []struct {
		method    string
		wantGated bool
	}{
		{http.MethodPost, true},
		{http.MethodPut, true},
		{http.MethodPatch, true},
		{http.MethodDelete, true},
	} {
		t.Run(tc.method, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, "/api/v1/policies", strings.NewReader(`{}`))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s status = %d, want 403", tc.method, w.Code)
			}
		})
	}
}

func TestProxy_ReadOnlyRPC_BypassesVerbGate(t *testing.T) {
	// /policies/<id>/test and /policies/validate are POSTs that perform
	// no server-side mutation. They MUST bypass the AllowWrites gate so
	// the Playground UX works in the default read-only deployment.
	cfg := &Config{PolicyManagerURL: "http://upstream.invalid", AllowWrites: false}
	proxy, err := NewProxyHandler(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewProxyHandler: %v", err)
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Handle(http.MethodPost, "/api/v1/*proxyPath", proxy)

	for _, tc := range []struct {
		name string
		path string
	}{
		{"playground test", "/api/v1/policies/security-baseline/test"},
		{"playground test with uuid id", "/api/v1/policies/abc-123/test"},
		{"validate", "/api/v1/policies/validate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(`{}`))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code == http.StatusForbidden {
				t.Fatalf("%s must NOT be 403'd by the write gate; got %d body=%s", tc.path, w.Code, w.Body.String())
			}
		})
	}
}

func TestIsReadOnlyRPC_GuardRails(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		path   string
		want   bool
	}{
		{"test endpoint", "POST", "/policies/security-baseline/test", true},
		{"validate endpoint", "POST", "/policies/validate", true},
		{"GET does not match", "GET", "/policies/security-baseline/test", false},
		{"create policy (real write)", "POST", "/policies", false},
		{"update policy (real write)", "PUT", "/policies/security-baseline", false},
		{"empty id between policies and /test", "POST", "/policies//test", false},
		{"nested path masquerading as test", "POST", "/policies/foo/bar/test", false},
		{"prefix match but different suffix", "POST", "/policies/foo/testify", false},
		{"trailing slash", "POST", "/policies/foo/test/", false},
		{"validate with extra segment", "POST", "/policies/validate/x", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := isReadOnlyRPC(tc.method, tc.path)
			if got != tc.want {
				t.Errorf("isReadOnlyRPC(%q, %q) = %v, want %v", tc.method, tc.path, got, tc.want)
			}
		})
	}
}

// TestParseExposition_DoesNotPanicOnRealInput guards against prometheus/common
// v0.67's "Invalid name validation scheme requested: unset" panic. Without the
// init() in metrics.go that sets NameValidationScheme, this test panics on
// the first HELP/TYPE comment because TextParser.setOrCreateCurrentMF calls
// IsValidMetricName against an Unset scheme.
func TestParseExposition_DoesNotPanicOnRealInput(t *testing.T) {
	exposition := `# HELP kube_policies_admission_requests_total Total admission requests.
# TYPE kube_policies_admission_requests_total counter
kube_policies_admission_requests_total{status="allowed"} 12
kube_policies_admission_requests_total{status="denied"} 3
# HELP kube_policies_audit_buffer_size Current audit buffer size.
# TYPE kube_policies_audit_buffer_size gauge
kube_policies_audit_buffer_size 7
`
	families, err := parseExposition(strings.NewReader(exposition))
	if err != nil {
		t.Fatalf("parseExposition: %v", err)
	}
	if _, ok := families["kube_policies_admission_requests_total"]; !ok {
		t.Errorf("expected admission_requests_total family; got keys %v", families)
	}
	if _, ok := families["kube_policies_audit_buffer_size"]; !ok {
		t.Errorf("expected audit_buffer_size family; got keys %v", families)
	}
}

// TestMetricsHandler_AggregatesUpstreamFamilies verifies that the /api/metrics/summary
// handler scrapes both upstream /metrics endpoints, derives the typed summary, and
// returns 200 with the expected fields populated.
func TestMetricsHandler_AggregatesUpstreamFamilies(t *testing.T) {
	pm := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = io.WriteString(w, `# HELP kube_policies_policy_loaded_total Loaded policies.
# TYPE kube_policies_policy_loaded_total gauge
kube_policies_policy_loaded_total 3
# HELP kube_policies_policy_evaluations_total Policy evaluations.
# TYPE kube_policies_policy_evaluations_total counter
kube_policies_policy_evaluations_total{rule_id="r1",result="denied"} 5
kube_policies_policy_evaluations_total{rule_id="r2",result="denied"} 2
kube_policies_policy_evaluations_total{rule_id="r3",result="allowed"} 99
`)
	}))
	defer pm.Close()

	aw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		_, _ = io.WriteString(w, `# HELP kube_policies_admission_requests_total Admission requests.
# TYPE kube_policies_admission_requests_total counter
kube_policies_admission_requests_total{status="allowed"} 12
kube_policies_admission_requests_total{status="denied"} 3
# HELP kube_policies_audit_buffer_size Audit buffer.
# TYPE kube_policies_audit_buffer_size gauge
kube_policies_audit_buffer_size 7
`)
	}))
	defer aw.Close()

	cfg := &Config{
		PolicyManagerMetricsURL:    pm.URL,
		AdmissionWebhookMetricsURL: aw.URL,
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/metrics/summary", NewMetricsHandler(cfg, zap.NewNop()))

	req := httptest.NewRequest(http.MethodGet, "/api/metrics/summary", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	for _, want := range []string{
		`"policies_loaded":3`,
		`"policy_manager_degraded":false`,
		`"admission_webhook_degraded":false`,
		`"rule_id":"r1"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q; got %s", want, body)
		}
	}
}

// TestMetricsHandler_ReportsDegradedOnScrapeFailure verifies acceptance #8:
// an unreachable upstream sets the per-source degraded flag and returns 200,
// never a 5xx.
func TestMetricsHandler_ReportsDegradedOnScrapeFailure(t *testing.T) {
	cfg := &Config{
		PolicyManagerMetricsURL:    "http://127.0.0.1:1/dead",
		AdmissionWebhookMetricsURL: "http://127.0.0.1:1/dead",
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/metrics/summary", NewMetricsHandler(cfg, zap.NewNop()))

	req := httptest.NewRequest(http.MethodGet, "/api/metrics/summary", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 even when upstream is unreachable; body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"policy_manager_degraded":true`) {
		t.Errorf("body must report policy_manager_degraded:true; got %s", body)
	}
	if !strings.Contains(body, `"admission_webhook_degraded":true`) {
		t.Errorf("body must report admission_webhook_degraded:true; got %s", body)
	}
}

func TestProxy_VerbGate_AllowsWritesWhenEnabled_ButUpstreamDown(t *testing.T) {
	// We don't have a real upstream; we just verify the verb gate does NOT
	// short-circuit when AllowWrites=true — the request reaches the proxy,
	// which then fails with 502 because http://upstream.invalid doesn't
	// resolve. That distinguishes "gate blocked" (403) from "gate passed".
	cfg := &Config{PolicyManagerURL: "http://upstream.invalid", AllowWrites: true}
	proxy, err := NewProxyHandler(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewProxyHandler: %v", err)
	}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())
	r.Handle(http.MethodPost, "/api/v1/*proxyPath", proxy)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code == http.StatusForbidden {
		t.Fatalf("AllowWrites=true must not yield 403; got %d", w.Code)
	}
	if w.Code != http.StatusBadGateway {
		t.Logf("note: upstream unreachable, got %d (expected 502); body=%s", w.Code, w.Body.String())
	}
}

// newStreamTestRouter returns a gin engine with the SSE stream route wired up.
func newStreamTestRouter(ctx context.Context, cfg *Config) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/api/decisions/stream", NewStreamHandler(ctx, cfg, zap.NewNop()))
	return r
}

// TestStreamHandler_FansOutFromUpstream verifies that two browser clients both
// receive events published by the single upstream SSE subscription.
func TestStreamHandler_FansOutFromUpstream(t *testing.T) {
	upstreamConnected := make(chan struct{}, 1)
	sendEvents := make(chan struct{})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case upstreamConnected <- struct{}{}:
		default:
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		// Wait until test signals to send events.
		<-sendEvents
		fmt.Fprint(w, "data: {\"decision\":\"DENY\",\"kind\":\"Pod\",\"rule_id\":\"r1\",\"policy_id\":\"p1\",\"timestamp\":\"2026-01-01T00:00:00Z\"}\n\n")
		fmt.Fprint(w, "data: {\"decision\":\"ALLOW\",\"kind\":\"Pod\",\"rule_id\":\"r2\",\"policy_id\":\"p1\",\"timestamp\":\"2026-01-01T00:00:01Z\"}\n\n")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
	}))
	defer upstream.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &Config{PolicyManagerStreamURL: upstream.URL}
	srv := httptest.NewServer(newStreamTestRouter(ctx, cfg))
	defer srv.Close()

	const numClients = 2
	type result struct {
		events []string
		err    error
	}
	ch := make(chan result, numClients)

	for range numClients {
		go func() {
			resp, err := http.Get(srv.URL + "/api/decisions/stream") //nolint:noctx
			if err != nil {
				ch <- result{err: err}
				return
			}
			defer resp.Body.Close()
			scanner := bufio.NewScanner(resp.Body)
			var events []string
			for scanner.Scan() {
				line := scanner.Text()
				if strings.HasPrefix(line, "data: ") {
					events = append(events, strings.TrimPrefix(line, "data: "))
					if len(events) >= 2 {
						ch <- result{events: events}
						return
					}
				}
			}
			ch <- result{events: events}
		}()
	}

	// Wait for the upstream goroutine to connect before sending events.
	select {
	case <-upstreamConnected:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received a connection")
	}
	// Brief pause so both clients have subscribed to the hub.
	time.Sleep(20 * time.Millisecond)
	close(sendEvents)

	for i := range numClients {
		select {
		case r := <-ch:
			if r.err != nil {
				t.Errorf("client %d: %v", i, r.err)
			} else if len(r.events) < 2 {
				t.Errorf("client %d: got %d events, want 2; events=%v", i, len(r.events), r.events)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("client %d timed out waiting for events", i)
		}
	}
}

// TestStreamHandler_OneUpstreamConnection verifies that 5 concurrent browser
// clients share a single upstream GET (sync.Once semantics).
func TestStreamHandler_OneUpstreamConnection(t *testing.T) {
	var getCount atomic.Int32

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		getCount.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
	}))
	defer upstream.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg := &Config{PolicyManagerStreamURL: upstream.URL}
	srv := httptest.NewServer(newStreamTestRouter(ctx, cfg))
	defer srv.Close()

	clientCtx, clientCancel := context.WithCancel(context.Background())
	defer clientCancel()

	const numClients = 5
	var wg sync.WaitGroup
	for range numClients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(clientCtx, http.MethodGet,
				srv.URL+"/api/decisions/stream", nil)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)
		}()
	}

	// Let all clients connect and the upstream goroutine start.
	time.Sleep(100 * time.Millisecond)

	if n := getCount.Load(); n != 1 {
		t.Errorf("upstream received %d GET requests, want exactly 1", n)
	}

	clientCancel()
	wg.Wait()
}

// TestStreamHandler_BrowserDisconnect verifies that cancelling a browser
// request context cleans up the per-browser goroutine without leaking.
// The upstream subscriber context is also cancelled before the final goroutine
// count so the subscriber and its upstream HTTP connection both exit cleanly,
// making the assertion stable across platforms.
func TestStreamHandler_BrowserDisconnect(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-r.Context().Done()
	}))
	defer upstream.Close()

	ctx, cancel := context.WithCancel(context.Background())
	// cancel is called explicitly below; not deferred so we control timing.

	cfg := &Config{PolicyManagerStreamURL: upstream.URL}
	srv := httptest.NewServer(newStreamTestRouter(ctx, cfg))
	defer srv.Close()

	before := runtime.NumGoroutine()

	clientCtx, clientCancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		req, _ := http.NewRequestWithContext(clientCtx, http.MethodGet,
			srv.URL+"/api/decisions/stream", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
	}()

	// Let the upstream subscriber goroutine start and the browser goroutine settle.
	time.Sleep(50 * time.Millisecond)

	// Disconnect the browser client.
	clientCancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("client goroutine did not exit after context cancel")
	}

	// Cancel the upstream subscriber so it exits too, then allow cleanup.
	cancel()
	time.Sleep(100 * time.Millisecond)

	after := runtime.NumGoroutine()
	// With both the browser goroutine and upstream subscriber exited,
	// the count should be close to baseline. Allow a small tolerance for
	// runtime and httptest.Server housekeeping goroutines.
	const tolerance = 3
	if after > before+tolerance {
		t.Errorf("possible goroutine leak: before=%d after=%d (delta=%d, tolerance=%d)",
			before, after, after-before, tolerance)
	}
}
