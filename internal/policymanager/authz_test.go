package policymanager

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// rbacTestConfig binds one OIDC group per role so a minted token's groups claim
// selects the principal's effective role. No DefaultRole => unmapped principals
// resolve to RoleNone.
func rbacTestConfig() config.RBACConfig {
	return config.RBACConfig{
		RoleBindings: []config.RoleBinding{
			{Role: "viewer", Groups: []string{"grp-viewer"}},
			{Role: "editor", Groups: []string{"grp-editor"}},
			{Role: "admin", Groups: []string{"grp-admin"}},
		},
	}
}

// tokenForGroups mints a valid token whose groups claim is set to groups.
func tokenForGroups(t *testing.T, groups []string) string {
	t.Helper()
	claims := validClaims()
	if groups == nil {
		delete(claims, "groups")
	} else {
		claims["groups"] = groups
	}
	return mintToken(t, jose.RS256, claims)
}

// doRBACRequest serves method+path through the real NewAPIRouter (so
// c.FullPath() matches production templates) with the given bearer token and
// returns the status code.
func doRBACRequest(t *testing.T, router http.Handler, method, path, token string, body string) int {
	t.Helper()
	var reader *strings.Reader
	if body != "" {
		reader = strings.NewReader(body)
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w.Code
}

// TestRBACMiddleware_RoleVerbMatrix asserts the EXACT status returned per route
// for each role through the real NewAPIRouter (FIX I/J). Allowed cells assert
// the real handler's status (200/201/204, or 501 for the deploy stub) so a
// no-op middleware that simply passed
// every request through could not satisfy the denied cells, and a broken
// handler wiring could not satisfy the allowed cells. Denied cells assert 403.
//
// The route set is driven so that the minimum-role boundary (the role one tier
// below the requirement => 403, the exact required role => allowed) is proven
// for every distinct tier transition, including the three viewer-level POST
// RPCs (test/validate/evaluate) — the only viewer POSTs, so a mis-tiering of any
// of them is caught here.
func TestRBACMiddleware_RoleVerbMatrix(t *testing.T) {
	v := newHermeticVerifier(t)
	authCfg := testAuthConfig()
	rbacCfg := rbacTestConfig()
	m := newTestManagerWithPolicy(t, newPrivilegedPolicy())
	router := NewAPIRouter(m, authCfg, rbacCfg, v, config.RateLimitConfig{}, nil)

	tokens := map[string]string{
		"none":   tokenForGroups(t, []string{"grp-unmapped"}),
		"viewer": tokenForGroups(t, []string{"grp-viewer"}),
		"editor": tokenForGroups(t, []string{"grp-editor"}),
		"admin":  tokenForGroups(t, []string{"grp-admin"}),
	}

	// A valid pod body so TestPolicy (viewer RPC) reaches a real 200 rather than
	// a 400; the policy "test-no-privileged" exists on m.
	validPodBody := `{"apiVersion":"v1","kind":"Pod","metadata":{"name":"good","namespace":"default"},"spec":{"securityContext":{"privileged":false},"containers":[{"name":"c","image":"nginx:1.25"}]}}`
	// A minimal valid policy body for /policies/validate and /policies/evaluate.
	validatePolicyBody := `{"name":"p","rules":[{"id":"r","name":"r","rego":"package kube_policies\nevaluate = {\"allowed\": true}"}]}`
	evaluateBody := `{"resource":{"apiVersion":"v1","kind":"Pod","metadata":{"name":"x"}},"policy":{"name":"p","rules":[{"id":"r","name":"r","rego":"package kube_policies\nevaluate = {\"allowed\": true}"}]}}`

	type tc struct {
		role     string
		method   string
		path     string
		body     string
		wantCode int
	}
	cases := []tc{
		// ---- viewer-tier reads (require RoleViewer) ----
		// boundary: none => 403, viewer => real handler status.
		{"none", http.MethodGet, "/api/v1/policies", "", http.StatusForbidden},
		{"viewer", http.MethodGet, "/api/v1/policies", "", http.StatusOK},
		{"viewer", http.MethodGet, "/api/v1/policies/test-no-privileged", "", http.StatusOK},
		{"viewer", http.MethodGet, "/api/v1/policies/test-no-privileged/status", "", http.StatusNotImplemented},
		{"viewer", http.MethodGet, "/api/v1/bundles", "", http.StatusOK},
		{"none", http.MethodGet, "/api/v1/bundles", "", http.StatusForbidden},
		{"viewer", http.MethodGet, "/api/v1/exceptions", "", http.StatusOK},
		{"viewer", http.MethodGet, "/api/v1/compliance/reports", "", http.StatusOK},
		{"viewer", http.MethodGet, "/api/v1/compliance/frameworks", "", http.StatusOK},

		// ---- viewer-tier POST RPCs (the ONLY viewer-level POSTs) ----
		// boundary: none => 403, viewer => real handler status.
		{"none", http.MethodPost, "/api/v1/policies/test-no-privileged/test", validPodBody, http.StatusForbidden},
		{"viewer", http.MethodPost, "/api/v1/policies/test-no-privileged/test", validPodBody, http.StatusOK},
		{"none", http.MethodPost, "/api/v1/policies/validate", validatePolicyBody, http.StatusForbidden},
		{"viewer", http.MethodPost, "/api/v1/policies/validate", validatePolicyBody, http.StatusOK},
		{"none", http.MethodPost, "/api/v1/policies/evaluate", evaluateBody, http.StatusForbidden},
		{"viewer", http.MethodPost, "/api/v1/policies/evaluate", evaluateBody, http.StatusOK},

		// ---- editor-tier writes (require RoleEditor) ----
		// boundary: viewer => 403, editor => real handler status.
		{"viewer", http.MethodPost, "/api/v1/policies", `{"id":"newp","name":"x","rules":[{"id":"r","name":"r","rego":"package kube_policies\nevaluate = {\"allowed\": true}"}]}`, http.StatusForbidden},
		{"editor", http.MethodPost, "/api/v1/policies", `{"id":"newp","name":"x","rules":[{"id":"r","name":"r","rego":"package kube_policies\nevaluate = {\"allowed\": true}"}]}`, http.StatusCreated},
		{"viewer", http.MethodPut, "/api/v1/policies/test-no-privileged", `{"name":"x","rules":[{"id":"r","name":"r","rego":"package kube_policies\nevaluate = {\"allowed\": true}"}]}`, http.StatusForbidden},
		{"editor", http.MethodPut, "/api/v1/policies/test-no-privileged", `{"name":"x","rules":[{"id":"r","name":"r","rego":"package kube_policies\nevaluate = {\"allowed\": true}"}]}`, http.StatusOK},
		{"viewer", http.MethodDelete, "/api/v1/policies/test-no-privileged", "", http.StatusForbidden},
		{"editor", http.MethodDelete, "/api/v1/policies/test-no-privileged", "", http.StatusNoContent},
		{"viewer", http.MethodPost, "/api/v1/bundles", `{"id":"b","name":"b"}`, http.StatusForbidden},
		{"editor", http.MethodPost, "/api/v1/bundles", `{"id":"b","name":"b"}`, http.StatusCreated},
		{"viewer", http.MethodPost, "/api/v1/exceptions", `{"id":"e","name":"e"}`, http.StatusForbidden},
		{"editor", http.MethodPost, "/api/v1/exceptions", `{"id":"e","name":"e"}`, http.StatusCreated},

		// ---- admin-tier privileged ops (require RoleAdmin) ----
		// boundary: editor => 403, admin => real handler status. deploy is still a
		// 501 stub; compliance-report generation is now implemented (AUD-WU-19) and
		// returns 201 for an admin principal.
		{"editor", http.MethodPost, "/api/v1/policies/test-no-privileged/deploy", "", http.StatusForbidden},
		{"admin", http.MethodPost, "/api/v1/policies/test-no-privileged/deploy", "", http.StatusNotImplemented},
		{"editor", http.MethodPost, "/api/v1/compliance/reports", `{"framework":"cis"}`, http.StatusForbidden},
		{"admin", http.MethodPost, "/api/v1/compliance/reports", `{"framework":"cis"}`, http.StatusCreated},
	}

	for _, c := range cases {
		name := c.role + " " + c.method + " " + c.path
		t.Run(name, func(t *testing.T) {
			code := doRBACRequest(t, router, c.method, c.path, tokens[c.role], c.body)
			assert.Equal(t, c.wantCode, code)
		})
	}
}

// TestAPIRouter_ManagementPlaneRequiresAuthN exercises the REAL NewAPIRouter
// with auth enabled (FIX I.2): a management route with no Authorization header,
// and one with a garbage bearer, must both be 401 from the OIDC middleware.
func TestAPIRouter_ManagementPlaneRequiresAuthN(t *testing.T) {
	v := newHermeticVerifier(t)
	m := newTestManagerWithPolicy(t, newPrivilegedPolicy())
	router := NewAPIRouter(m, testAuthConfig(), rbacTestConfig(), v, config.RateLimitConfig{}, nil)

	t.Run("no bearer => 401", func(t *testing.T) {
		code := doRBACRequest(t, router, http.MethodGet, "/api/v1/policies", "", "")
		assert.Equal(t, http.StatusUnauthorized, code)
	})
	t.Run("garbage bearer => 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", strings.NewReader(""))
		req.Header.Set("Authorization", "Bearer garbage")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}

// TestAPIRouter_DecisionsPlaneIsOIDCExempt confirms the machine-plane boundary
// through NewAPIRouter with auth ENABLED (FIX I.3, updated Inc7 Stream A): the
// decisions read feeds (/stream, /recent) and the ingest endpoint (/internal)
// are NOT behind the human OIDC middleware — they are service-to-service. But
// they are NOT unauthenticated either: each rejects via the SERVICE-token path
// (TokenReview / static), so with NO bearer they return 401 from the decisions
// auth layer, NOT from OIDC.
//
// Proof that 401 comes from the service path (not OIDC): a garbage OIDC bearer
// passed to a management route 401s via OIDC; here we assert the decisions
// routes 401 even though the group is constructed WITHOUT the OIDC middleware
// (router.go puts them in a separate group). The companion full-route matrix
// (TestAPIRouter_AllV1RoutesRequireServiceOrOIDCToken) proves the
// reachable-without-token contract for /healthz + /readyz.
func TestAPIRouter_DecisionsPlaneIsOIDCExempt(t *testing.T) {
	v := newHermeticVerifier(t)
	m := newTestManagerWithPolicy(t, newPrivilegedPolicy())
	// No reviewer and no static token configured: the decisions auth layer must
	// still reject an unauthenticated read (an empty verifier is not a wildcard).
	router := NewAPIRouter(m, testAuthConfig(), rbacTestConfig(), v, config.RateLimitConfig{}, nil)

	// stream + recent are no longer unauthenticated: with no token they 401 via
	// the DecisionsReadAuth service-token middleware.
	for _, path := range []string{"/api/v1/decisions/recent", "/api/v1/decisions/stream"} {
		code := doRBACRequest(t, router, http.MethodGet, path, "", "")
		assert.Equal(t, http.StatusUnauthorized, code,
			"%s must reject an unauthenticated read via the service-token path, got %d", path, code)
	}

	// /internal stays TokenReview/static-gated (its own webhook-SA pin); no token
	// => 401, not OIDC.
	code := doRBACRequest(t, router, http.MethodPost, "/api/v1/decisions/internal", "", "")
	assert.Equal(t, http.StatusUnauthorized, code,
		"decisions/internal must stay service-token-gated, got %d", code)

	// Confirm the 401 is from the service-token layer, not OIDC: a request
	// carrying a VALID OIDC bearer is still rejected by the decisions read layer
	// (it does not consult OIDC at all), whereas a management route would admit
	// the same valid OIDC token. This distinguishes "service-authed" from
	// "OIDC human-authed".
	validOIDC := tokenForGroups(t, []string{"grp-viewer"})
	code = doRBACRequest(t, router, http.MethodGet, "/api/v1/decisions/recent", validOIDC, "")
	assert.Equal(t, http.StatusUnauthorized, code,
		"the decisions read path must NOT honor an OIDC human token (it is service-authed), got %d", code)
	// Same OIDC token on a management read is admitted (200) — proves the token
	// itself is valid and the difference is the auth lane, not the token.
	code = doRBACRequest(t, router, http.MethodGet, "/api/v1/policies", validOIDC, "")
	assert.Equal(t, http.StatusOK, code,
		"the same OIDC token must be accepted on the OIDC-gated management plane, got %d", code)
}

// TestRBACMiddleware_UnmappedRouteDeniedByDefault confirms a method/path absent
// from the requiredRoles table is denied even for an admin principal.
func TestRBACMiddleware_UnmappedRouteDeniedByDefault(t *testing.T) {
	rbac := rbacTestConfig()
	p := &Principal{Subject: "alice", Groups: []string{"grp-admin"}}
	require.Equal(t, RoleAdmin, roleForPrincipal(p, rbac))

	// A PATCH on a real path is not in the table.
	_, known := requiredRole(http.MethodPatch, "/api/v1/policies")
	assert.False(t, known)
}

func TestRoleForPrincipal(t *testing.T) {
	rbac := rbacTestConfig()

	t.Run("highest matching role wins", func(t *testing.T) {
		p := &Principal{Groups: []string{"grp-viewer", "grp-admin"}}
		assert.Equal(t, RoleAdmin, roleForPrincipal(p, rbac))
	})
	t.Run("no match and empty default => none", func(t *testing.T) {
		p := &Principal{Groups: []string{"grp-nope"}}
		assert.Equal(t, RoleNone, roleForPrincipal(p, rbac))
	})
	t.Run("no match falls back to default role", func(t *testing.T) {
		rbacWithDefault := rbac
		rbacWithDefault.DefaultRole = "viewer"
		p := &Principal{Groups: []string{"grp-nope"}}
		assert.Equal(t, RoleViewer, roleForPrincipal(p, rbacWithDefault))
	})
	t.Run("nil principal => none", func(t *testing.T) {
		assert.Equal(t, RoleNone, roleForPrincipal(nil, rbac))
	})
}

// TestRoleBindingDrivesEditorGate is the IAM-WU-13 honesty proof for
// security.rbac.role_bindings: a config that maps a group to "editor" must
// actually let that principal pass the editor-gated mutation route
// (POST /api/v1/policies → RoleEditor), while a viewer-only principal is denied
// the same gate. It exercises the real resolver (roleForPrincipal) against the
// real route table (requiredRole), so the docs claim that role_bindings control
// access is anchored in the code, not asserted in prose.
func TestRoleBindingDrivesEditorGate(t *testing.T) {
	rbac := config.RBACConfig{
		RoleBindings: []config.RoleBinding{
			{Role: "editor", Groups: []string{"platform"}},
			{Role: "viewer", Groups: []string{"readers"}},
		},
	}

	needed, known := requiredRole(http.MethodPost, "/api/v1/policies")
	require.True(t, known, "POST /api/v1/policies must be in the route table")
	require.Equal(t, RoleEditor, needed, "creating a policy requires editor")

	editor := &Principal{Username: "alice", Groups: []string{"platform"}}
	assert.GreaterOrEqual(t, int(roleForPrincipal(editor, rbac)), int(needed),
		"an editor-bound principal must satisfy the editor gate")

	viewer := &Principal{Username: "bob", Groups: []string{"readers"}}
	assert.Less(t, int(roleForPrincipal(viewer, rbac)), int(needed),
		"a viewer-only principal must be denied the editor gate")
}

func TestParseRole(t *testing.T) {
	for name, want := range map[string]Role{
		"viewer": RoleViewer,
		"editor": RoleEditor,
		"admin":  RoleAdmin,
	} {
		got, ok := parseRole(name)
		assert.True(t, ok)
		assert.Equal(t, want, got)
	}
	got, ok := parseRole("superuser")
	assert.False(t, ok)
	assert.Equal(t, RoleNone, got)
}
