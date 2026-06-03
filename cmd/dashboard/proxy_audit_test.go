package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/audit"
	"github.com/Jibbscript/kube-policies/internal/config"
)

// newAuditLogger builds a real audit.Logger writing to a temp file so tests
// can read emitted records without capturing stdout.
func newAuditLogger(t *testing.T) (*audit.Logger, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	cfg := &config.AuditConfig{
		Enabled:    true,
		Backend:    "file",
		BufferSize: 64,
		Config:     map[string]string{"filename": path},
	}
	l, err := audit.NewLogger(cfg, audit.WithLogger(zap.NewNop()))
	if err != nil {
		t.Fatalf("newAuditLogger: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l, path
}

// readAuditRecords flushes + closes the logger, then reads all JSON records
// from the file. Returns the slice of raw decoded maps.
func readAuditRecords(t *testing.T, l *audit.Logger, path string) []map[string]interface{} {
	t.Helper()
	if err := l.Close(); err != nil {
		t.Fatalf("audit Close: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit file: %v", err)
	}
	var records []map[string]interface{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("unmarshal audit record %q: %v", line, err)
		}
		records = append(records, m)
	}
	return records
}

// newProxyRouter wires a gin router with the proxy handler. An optional
// principal is injected into the context to simulate authenticated users.
func newProxyRouter(t *testing.T, cfg *Config, auditLog *audit.Logger, upstream string, p *principal) *gin.Engine {
	t.Helper()
	cfg.PolicyManagerURL = upstream
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if p != nil {
			c.Set(principalContextKey, p)
		}
		c.Next()
	})
	proxy, err := NewProxyHandler(cfg, nil, zap.NewNop(), auditLog)
	if err != nil {
		t.Fatalf("NewProxyHandler: %v", err)
	}
	for _, m := range []string{
		http.MethodGet, http.MethodHead, http.MethodPost,
		http.MethodPut, http.MethodPatch, http.MethodDelete,
	} {
		r.Handle(m, "/api/v1/*proxyPath", proxy)
	}
	return r
}

// TestProxyAudit_MutatingRequest_AllowWritesTrue verifies that a mutating
// request reaching the upstream produces a DashboardWriteAttempt record with
// allow_writes=true and the authenticated user's identity (AUD-WU-13).
func TestProxyAudit_MutatingRequest_AllowWritesTrue(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	auditLog, path := newAuditLogger(t)
	cfg := &Config{AllowWrites: true}
	p := &principal{Username: "alice", Subject: "alice", IDToken: "SHOULD-NOT-APPEAR"}

	r := newProxyRouter(t, cfg, auditLog, upstream.URL, p)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", strings.NewReader(`{}`))
	r.ServeHTTP(httptest.NewRecorder(), req)

	records := readAuditRecords(t, auditLog, path)
	if len(records) == 0 {
		t.Fatal("expected at least one audit record; got none")
	}

	rec := records[0]
	if got := rec["event_type"]; got != "DashboardWriteAttempt" {
		t.Errorf("event_type = %q, want DashboardWriteAttempt", got)
	}
	meta, _ := rec["metadata"].(map[string]interface{})
	if meta == nil {
		t.Fatalf("record has no metadata field")
	}
	if got := meta["user"]; got != "alice" {
		t.Errorf("metadata.user = %q, want alice", got)
	}
	if got := meta["method"]; got != http.MethodPost {
		t.Errorf("metadata.method = %q, want POST", got)
	}
	if got, _ := meta["allow_writes"].(bool); !got {
		t.Errorf("metadata.allow_writes = %v, want true", meta["allow_writes"])
	}
	// Confirm the raw ID token is not present anywhere in the record.
	raw, _ := json.Marshal(rec)
	if strings.Contains(string(raw), "SHOULD-NOT-APPEAR") {
		t.Errorf("audit record must not contain the raw IDToken; got %s", raw)
	}
}

// TestProxyAudit_MutatingRequest_AllowWritesFalse verifies that a denied
// write (ALLOW_WRITES=false → 403) still produces a DashboardWriteAttempt
// record with allow_writes=false. This is the key case only the dashboard
// can audit (the policy-manager never sees the request).
func TestProxyAudit_MutatingRequest_AllowWritesFalse(t *testing.T) {
	auditLog, path := newAuditLogger(t)
	cfg := &Config{
		PolicyManagerURL: "http://upstream.invalid", // never reached
		AllowWrites:      false,
	}
	p := &principal{Username: "bob", Subject: "bob"}

	r := newProxyRouter(t, cfg, auditLog, "http://upstream.invalid", p)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/policies/foo", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}

	records := readAuditRecords(t, auditLog, path)
	if len(records) == 0 {
		t.Fatal("denied write must still produce an audit record")
	}

	rec := records[0]
	if got := rec["event_type"]; got != "DashboardWriteAttempt" {
		t.Errorf("event_type = %q, want DashboardWriteAttempt", got)
	}
	meta, _ := rec["metadata"].(map[string]interface{})
	if meta == nil {
		t.Fatalf("record has no metadata field")
	}
	if got, ok := meta["allow_writes"].(bool); ok && got {
		t.Errorf("metadata.allow_writes = true, want false")
	}
	if got := meta["user"]; got != "bob" {
		t.Errorf("metadata.user = %q, want bob", got)
	}
}

// TestProxyAudit_UnauthenticatedUser verifies that when authModeDisabled is
// in effect (principalFromContext returns false) the audit record still emits
// with user="system:unauthenticated" rather than being dropped.
func TestProxyAudit_UnauthenticatedUser(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	auditLog, path := newAuditLogger(t)
	cfg := &Config{AllowWrites: true}
	// No principal injected — simulates authModeDisabled.
	r := newProxyRouter(t, cfg, auditLog, upstream.URL, nil)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/policies/bar", strings.NewReader(`{}`))
	r.ServeHTTP(httptest.NewRecorder(), req)

	records := readAuditRecords(t, auditLog, path)
	if len(records) == 0 {
		t.Fatal("expected audit record for unauthenticated mutating request")
	}
	meta, _ := records[0]["metadata"].(map[string]interface{})
	if meta == nil {
		t.Fatalf("record has no metadata field")
	}
	if got := meta["user"]; got != "system:unauthenticated" {
		t.Errorf("metadata.user = %q, want system:unauthenticated", got)
	}
}

// TestProxyAudit_ReadOnlyRPC_NoRecord verifies that read-only RPC POSTs
// (POST /policies/validate, POST /policies/<id>/test) do NOT produce an audit
// record — they persist nothing and must not inflate the audit trail.
func TestProxyAudit_ReadOnlyRPC_NoRecord(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	for _, tc := range []struct {
		name string
		path string
	}{
		{"validate", "/api/v1/policies/validate"},
		{"test", "/api/v1/policies/security-baseline/test"},
		{"evaluate", "/api/v1/policies/evaluate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auditLog, path := newAuditLogger(t)
			cfg := &Config{AllowWrites: false} // gate irrelevant for RPC
			r := newProxyRouter(t, cfg, auditLog, upstream.URL, nil)

			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(`{}`))
			r.ServeHTTP(httptest.NewRecorder(), req)

			records := readAuditRecords(t, auditLog, path)
			if len(records) != 0 {
				t.Errorf("%s: expected no audit record for read-only RPC, got %d", tc.name, len(records))
			}
		})
	}
}

// TestProxyAudit_GET_NoRecord verifies that GET requests (reads) do not
// produce any DashboardWriteAttempt record.
func TestProxyAudit_GET_NoRecord(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer upstream.Close()

	auditLog, path := newAuditLogger(t)
	cfg := &Config{AllowWrites: true}
	r := newProxyRouter(t, cfg, auditLog, upstream.URL, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	r.ServeHTTP(httptest.NewRecorder(), req)

	records := readAuditRecords(t, auditLog, path)
	if len(records) != 0 {
		t.Errorf("GET must not produce an audit record; got %d", len(records))
	}
}
