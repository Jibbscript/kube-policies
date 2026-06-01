package policymanager

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAPIRouter_AllV1RoutesRequireServiceOrOIDCToken is the P3 exit-gate matrix
// (IAM-WU-01 / Inc7 Stream A): every /api/v1 route mounted by the REAL
// NewAPIRouter — management plane AND the decisions machine-plane — must reject
// an unauthenticated request (no token) AND a garbage bearer with 401, while the
// kubelet probe endpoints /healthz + /readyz stay reachable WITHOUT a token.
//
// The decisions read feeds (/decisions/stream, /recent) reject via the new
// DecisionsReadAuth service-token middleware; /decisions/internal via its own
// webhook-SA check; the management routes via the OIDC middleware. No /api/v1
// route is unauthenticated.
//
// The route list is enumerated explicitly here AND cross-checked against the
// live gin route table (router.Routes()) below, so a future route added to
// NewAPIRouter that is NOT added to this matrix fails the test — forcing every
// new route into 401 coverage rather than silently shipping unauthenticated.
func TestAPIRouter_AllV1RoutesRequireServiceOrOIDCToken(t *testing.T) {
	v := newHermeticVerifier(t)
	m := newTestManagerWithPolicy(t, newPrivilegedPolicy())
	// Auth enabled, but NO service tokens/reviewers configured: every route must
	// fail closed for an unauthenticated/garbage caller regardless.
	router := NewAPIRouter(m, testAuthConfig(), rbacTestConfig(), v)

	type route struct {
		method string
		path   string
	}
	// Every /api/v1 route NewAPIRouter mounts. Keep in sync with router.go; the
	// coverage assertion below fails if a mounted /api/v1 route is missing here.
	wantAuthed := []route{
		// Management plane (OIDC-gated).
		{http.MethodGet, "/api/v1/policies"},
		{http.MethodGet, "/api/v1/policies/some-id"},
		{http.MethodPost, "/api/v1/policies"},
		{http.MethodPut, "/api/v1/policies/some-id"},
		{http.MethodDelete, "/api/v1/policies/some-id"},
		{http.MethodPost, "/api/v1/policies/some-id/test"},
		{http.MethodPost, "/api/v1/policies/validate"},
		{http.MethodPost, "/api/v1/policies/evaluate"},
		{http.MethodPost, "/api/v1/policies/some-id/deploy"},
		{http.MethodGet, "/api/v1/policies/some-id/status"},
		{http.MethodGet, "/api/v1/bundles"},
		{http.MethodGet, "/api/v1/bundles/some-id"},
		{http.MethodPost, "/api/v1/bundles"},
		{http.MethodGet, "/api/v1/exceptions"},
		{http.MethodPost, "/api/v1/exceptions"},
		{http.MethodPut, "/api/v1/exceptions/some-id"},
		{http.MethodDelete, "/api/v1/exceptions/some-id"},
		{http.MethodGet, "/api/v1/compliance/reports"},
		{http.MethodPost, "/api/v1/compliance/reports"},
		{http.MethodGet, "/api/v1/compliance/frameworks"},
		// Decisions machine-plane (service-token-gated, NOT OIDC).
		{http.MethodPost, "/api/v1/decisions/internal"},
		{http.MethodGet, "/api/v1/decisions/stream"},
		{http.MethodGet, "/api/v1/decisions/recent"},
	}

	for _, r := range wantAuthed {
		t.Run("no token "+r.method+" "+r.path, func(t *testing.T) {
			code := doRBACRequest(t, router, r.method, r.path, "", "")
			assert.Equal(t, http.StatusUnauthorized, code,
				"%s %s with NO token must be 401", r.method, r.path)
		})
		t.Run("garbage bearer "+r.method+" "+r.path, func(t *testing.T) {
			req := httptest.NewRequest(r.method, r.path, strings.NewReader(""))
			req.Header.Set("Authorization", "Bearer garbage-not-a-jwt-or-sa-token")
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusUnauthorized, w.Code,
				"%s %s with a garbage bearer must be 401", r.method, r.path)
		})
	}

	// /healthz + /readyz are reachable WITHOUT a token (kubelet probes send none).
	for _, p := range []string{"/healthz", "/readyz"} {
		t.Run("open "+p, func(t *testing.T) {
			code := doRBACRequest(t, router, http.MethodGet, p, "", "")
			assert.Equal(t, http.StatusOK, code, "%s must be reachable without a token", p)
		})
	}

	// Coverage guard: every /api/v1 route in the live gin table must appear in
	// wantAuthed. Drives a future route into the matrix instead of letting it
	// ship without 401 coverage.
	covered := make(map[string]bool, len(wantAuthed))
	for _, r := range wantAuthed {
		covered[r.method+" "+routeTemplateForTest(r.path)] = true
	}
	for _, ri := range router.Routes() {
		if !strings.HasPrefix(ri.Path, "/api/v1") {
			continue
		}
		key := ri.Method + " " + ri.Path
		assert.Truef(t, covered[key],
			"route %s is mounted by NewAPIRouter but missing from the 401 matrix; add it to wantAuthed", key)
	}
}

// routeTemplateForTest maps the concrete request paths used in wantAuthed back
// to the gin route templates (":id" / "/*proxyPath" style) so the coverage
// guard can compare against router.Routes(). The policy-manager templates use
// ":id" for the single id param; the literal "some-id" segment in test paths is
// rewritten to ":id".
func routeTemplateForTest(path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if s == "some-id" {
			segs[i] = ":id"
		}
	}
	return strings.Join(segs, "/")
}

// TestRouteTemplateForTest_MatchesGinTable is a guard on the helper above: the
// rewritten templates for the id-bearing routes must exist verbatim in the live
// route table, so the coverage map keys line up.
func TestRouteTemplateForTest_MatchesGinTable(t *testing.T) {
	v := newHermeticVerifier(t)
	m := newTestManagerWithPolicy(t, newPrivilegedPolicy())
	router := NewAPIRouter(m, testAuthConfig(), rbacTestConfig(), v)

	templates := make(map[string]bool)
	for _, ri := range router.Routes() {
		templates[ri.Method+" "+ri.Path] = true
	}
	require.True(t, templates[http.MethodGet+" /api/v1/policies/:id"],
		"expected the :id template in the gin route table")
	require.Equal(t, "/api/v1/policies/:id", routeTemplateForTest("/api/v1/policies/some-id"))
}
