package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Jibbscript/kube-policies/internal/auth"
)

// metricsHandler returns the http.Handler newMetricsServer mounts for the given
// verifier, so the tests exercise the real mux (and the real auth wrapping)
// without binding a TCP listener.
func metricsHandler(t *testing.T, verifier *auth.TokenVerifier) http.Handler {
	t.Helper()
	srv := newMetricsServer(9092, verifier)
	if srv.Handler == nil {
		t.Fatal("newMetricsServer returned a server with a nil Handler")
	}
	return srv.Handler
}

// TestMetricsServer_AuthEnforcedWhenVerifierConfigured documents the production
// posture (IAM-WU-12): when TLS is on, main builds a configured verifier and
// /metrics requires the bearer token. /healthz stays open for kubelet probes.
func TestMetricsServer_AuthEnforcedWhenVerifierConfigured(t *testing.T) {
	const token = "dashboard-metrics-secret"
	h := metricsHandler(t, auth.NewTokenVerifier(token, ""))

	t.Run("no Authorization header => 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("/metrics without token = %d, want 401", w.Code)
		}
	})

	t.Run("wrong bearer token => 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.Header.Set("Authorization", "Bearer wrong-token")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("/metrics with wrong token = %d, want 401", w.Code)
		}
	})

	t.Run("correct bearer token => 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("/metrics with correct token = %d, want 200", w.Code)
		}
	})

	t.Run("healthz stays open (no token) => 200", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("/healthz without token = %d, want 200 (probe must stay open)", w.Code)
		}
	})
}

// TestMetricsServer_PreviousTokenAcceptedDuringRotation verifies the
// zero-downtime rotation window: both the current and the previous internal
// token authenticate a scrape (CRY-WU-14 semantics, reused here).
func TestMetricsServer_PreviousTokenAcceptedDuringRotation(t *testing.T) {
	const current, previous = "new-token", "old-token"
	h := metricsHandler(t, auth.NewTokenVerifier(current, previous))

	for name, tok := range map[string]string{"current": current, "previous": previous} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("/metrics with %s token = %d, want 200", name, w.Code)
			}
		})
	}
}

// TestMetricsServer_FailsClosedWhenTokenUnset documents the fail-closed posture:
// when TLS is on but the internal token is empty, main still builds a verifier
// (unconfigured). RequireBearer must 401 every scrape rather than serve metrics
// openly. /healthz stays open.
func TestMetricsServer_FailsClosedWhenTokenUnset(t *testing.T) {
	// NewTokenVerifier("", "") yields an unconfigured (but non-nil) verifier,
	// matching what main builds when cfg.TLSEnabled but INTERNAL_TOKEN is unset.
	v := auth.NewTokenVerifier("", "")
	if v.Configured() {
		t.Fatal("verifier built from empty tokens must report Configured()==false")
	}
	h := metricsHandler(t, v)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer anything")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("/metrics with unconfigured verifier = %d, want 401 (fail closed)", w.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200 (probe must stay open even when metrics fail closed)", w.Code)
	}
}

// TestMetricsServer_DevPostureNoVerifierServesOpenMetrics documents the dev
// posture HONESTLY: when TLS is off, main passes a nil verifier and /metrics is
// served WITHOUT authentication over plain HTTP. This is a tracked gap, not a
// hidden one — the test exists to make the behavior explicit and to fail loudly
// if someone later changes the nil-verifier contract.
func TestMetricsServer_DevPostureNoVerifierServesOpenMetrics(t *testing.T) {
	h := metricsHandler(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("/metrics with nil verifier (dev) = %d, want 200 (documented unauthenticated dev posture)", w.Code)
	}
}
