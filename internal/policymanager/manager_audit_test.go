package policymanager

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/Jibbscript/kube-policies/internal/audit"
	"github.com/Jibbscript/kube-policies/internal/config"
)

// IAM-WU-14: these tests prove that every persisting management-plane mutation
// records a ConfigurationChange audit event attributed to the authenticated
// OIDC principal (username + groups + source_ip), that no persisting mutation
// is ever recorded as system:unauthenticated while authN is enabled, that the
// dev-fallback (authN disabled) is honestly labeled system:unauthenticated, and
// that the non-persisting playground RPCs emit no ConfigurationChange event.

// auditTestRBAC binds the test token's "platform" group to editor, which is the
// minimum role the seven mutating routes require (see requiredRoles in authz.go).
func auditTestRBAC() config.RBACConfig {
	return config.RBACConfig{
		RoleBindings: []config.RoleBinding{
			{Role: "editor", Groups: []string{"platform"}},
		},
	}
}

// newFileAuditLogger builds a real file-backed audit.Logger writing JSON lines
// to a temp file, and returns the logger plus the file path. The logger is
// Closed via t.Cleanup so its background processor flushes before the test reads
// the file.
func newFileAuditLogger(t *testing.T) (*audit.Logger, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	cfg := &config.AuditConfig{
		Enabled:       true,
		Backend:       "file",
		Config:        map[string]string{"filename": path},
		BufferSize:    256,
		FlushInterval: "10ms",
	}
	l, err := audit.NewLogger(cfg, audit.WithLogger(zaptest.NewLogger(t)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = l.Close() })
	return l, path
}

// readAuditEvents Closes the logger (flushing the buffer) and parses every JSON
// line in the backing file. It is destructive to the logger, so callers pass a
// logger they no longer need to write to.
func readAuditEvents(t *testing.T, l *audit.Logger, path string) []audit.Event {
	t.Helper()
	// Close flushes the background processor's buffer to the file backend.
	require.NoError(t, l.Close())

	data, err := os.ReadFile(path)
	require.NoError(t, err)

	var events []audit.Event
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var ev audit.Event
		require.NoError(t, json.Unmarshal(line, &ev))
		events = append(events, ev)
	}
	require.NoError(t, scanner.Err())
	return events
}

// configChangeEvents filters to ConfigurationChange events only.
func configChangeEvents(events []audit.Event) []audit.Event {
	var out []audit.Event
	for _, ev := range events {
		if ev.EventType == "ConfigurationChange" {
			out = append(out, ev)
		}
	}
	return out
}

// authedRequest issues an authenticated request through the router with a valid
// RS256 token for the test principal (sub=alice, groups=[platform, sre]).
func authedRequest(t *testing.T, router http.Handler, method, target string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, target, rdr)
	req.Header.Set("Authorization", "Bearer "+mintToken(t, jose.RS256, validClaims()))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// newTestManager builds a Manager without booting controllers or background
// goroutines (NewManager only seeds the in-memory registry from bundled
// defaults; Start is not called here).
func newTestManager(t *testing.T) *Manager {
	t.Helper()
	cfg := &config.Config{
		Policy: config.PolicyConfig{FailureMode: "fail-closed"},
	}
	m, err := NewManager(cfg, zaptest.NewLogger(t))
	require.NoError(t, err)
	return m
}

// validRego is an allow-everything rule matching the engine.evaluatePolicy
// contract (data.kube_policies.evaluate returns {allowed,...}). It compiles for
// CreatePolicy/UpdatePolicy validation AND evaluates cleanly on the /test and
// /evaluate engine paths.
const validRego = `package kube_policies

evaluate = result {
	result := {"allowed": true}
}
`

func policyBody(t *testing.T, name string) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"name": name,
		"rules": []map[string]any{
			{"name": "r1", "rego": validRego},
		},
	})
	require.NoError(t, err)
	return b
}

// TestManagerAudit_AttributesAuthenticatedPrincipal is the core positive case:
// an authenticated POST/PUT/DELETE on /api/v1/policies each emits a
// ConfigurationChange event whose user_info matches the token principal and
// whose changes.source_ip is populated.
func TestManagerAudit_AttributesAuthenticatedPrincipal(t *testing.T) {
	m := newTestManager(t)
	auditLogger, path := newFileAuditLogger(t)
	m.SetAuditLogger(auditLogger)

	verifier := newHermeticVerifier(t)
	router := NewAPIRouter(m, testAuthConfig(), auditTestRBAC(), verifier)

	// CREATE
	w := authedRequest(t, router, http.MethodPost, "/api/v1/policies", policyBody(t, "p-create"))
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())
	var created map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	id, _ := created["id"].(string)
	require.NotEmpty(t, id)

	// UPDATE
	w = authedRequest(t, router, http.MethodPut, "/api/v1/policies/"+id, policyBody(t, "p-updated"))
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	// DELETE
	w = authedRequest(t, router, http.MethodDelete, "/api/v1/policies/"+id, nil)
	require.Equal(t, http.StatusNoContent, w.Code, "body: %s", w.Body.String())

	events := configChangeEvents(readAuditEvents(t, auditLogger, path))
	require.Len(t, events, 3, "expected one ConfigurationChange per mutation (CREATE, UPDATE, DELETE)")

	gotVerbs := map[string]bool{}
	for _, ev := range events {
		gotVerbs[ev.Operation] = true
		// Attribution: the token principal, not a fabricated identity.
		assert.Equal(t, "alice", ev.UserInfo.Username, "event %s must be attributed to the token username", ev.Operation)
		assert.Contains(t, ev.UserInfo.Groups, "platform", "event %s must carry the token group", ev.Operation)
		assert.Equal(t, "alice", ev.UserInfo.UID, "subject is recorded as UserInfo.UID")
		// source_ip must be present in the recorded changes.
		require.NotNil(t, ev.Metadata, "event %s must carry metadata", ev.Operation)
		changes, ok := ev.Metadata["changes"].(map[string]any)
		require.True(t, ok, "event %s metadata.changes must be a map", ev.Operation)
		srcIP, ok := changes["source_ip"].(string)
		require.True(t, ok, "event %s must record source_ip", ev.Operation)
		assert.NotEmpty(t, srcIP, "event %s source_ip must be non-empty", ev.Operation)
		// The affected resource is a policy.
		assert.Equal(t, "policy", ev.Metadata["resource"], "event %s resource", ev.Operation)
	}
	assert.True(t, gotVerbs["CREATE"], "CREATE event present")
	assert.True(t, gotVerbs["UPDATE"], "UPDATE event present")
	assert.True(t, gotVerbs["DELETE"], "DELETE event present")
}

// TestManagerAudit_UIDIsSubjectNotUsername proves that UserInfo.UID is wired to
// Principal.Subject (the OIDC sub claim) and UserInfo.Username is wired to the
// configured username_claim — and that these are recorded distinctly when they
// differ. validClaims() uses sub="alice" and username_claim="sub", so both are
// "alice" in the base test, masking any UID=Username regression. Here we mint a
// token where sub="uid-12345" and add a preferred_username="alice-display" claim,
// then configure username_claim=preferred_username so the two values are distinct.
// The test asserts UID==sub AND Username==preferred_username.
func TestManagerAudit_UIDIsSubjectNotUsername(t *testing.T) {
	m := newTestManager(t)
	auditLogger, path := newFileAuditLogger(t)
	m.SetAuditLogger(auditLogger)

	// Auth config using preferred_username as the username claim so
	// Subject ("uid-12345") != Username ("alice-display").
	authCfg := testAuthConfig()
	authCfg.UsernameClaim = "preferred_username"

	// Mint a token with distinct sub and preferred_username values.
	claims := validClaims()
	claims["sub"] = "uid-12345"
	claims["preferred_username"] = "alice-display"
	// Keep groups so the editor RBAC binding matches.

	verifier := newHermeticVerifier(t)
	router := NewAPIRouter(m, authCfg, auditTestRBAC(), verifier)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(policyBody(t, "uid-test")))
	req.Header.Set("Authorization", "Bearer "+mintToken(t, jose.RS256, claims))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	events := configChangeEvents(readAuditEvents(t, auditLogger, path))
	require.Len(t, events, 1)
	ev := events[0]
	assert.Equal(t, "alice-display", ev.UserInfo.Username,
		"Username must come from the configured username_claim (preferred_username), not sub")
	assert.Equal(t, "uid-12345", ev.UserInfo.UID,
		"UID must be the OIDC subject (sub), not the username_claim value")
	assert.NotEqual(t, ev.UserInfo.UID, ev.UserInfo.Username,
		"UID and Username must be distinct when sub != username_claim")
}

// TestManagerAudit_NoUnauthenticatedAttributionWhenAuthEnabled is the negative
// guard: with authN enabled, NO persisting-mutation event may be attributed to
// system:unauthenticated. Exercises every persisting route reachable for the
// editor token (policies, bundles, exceptions).
func TestManagerAudit_NoUnauthenticatedAttributionWhenAuthEnabled(t *testing.T) {
	m := newTestManager(t)
	auditLogger, path := newFileAuditLogger(t)
	m.SetAuditLogger(auditLogger)

	verifier := newHermeticVerifier(t)
	router := NewAPIRouter(m, testAuthConfig(), auditTestRBAC(), verifier)

	// Policy lifecycle.
	w := authedRequest(t, router, http.MethodPost, "/api/v1/policies", policyBody(t, "p"))
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())
	var created map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	policyID, _ := created["id"].(string)
	w = authedRequest(t, router, http.MethodPut, "/api/v1/policies/"+policyID, policyBody(t, "p2"))
	require.Equal(t, http.StatusOK, w.Code)
	w = authedRequest(t, router, http.MethodDelete, "/api/v1/policies/"+policyID, nil)
	require.Equal(t, http.StatusNoContent, w.Code)

	// Bundle create.
	bundleBody, _ := json.Marshal(map[string]any{"name": "b"})
	w = authedRequest(t, router, http.MethodPost, "/api/v1/bundles", bundleBody)
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	// Exception lifecycle.
	excBody, _ := json.Marshal(map[string]any{"name": "e", "policy_id": "pid"})
	w = authedRequest(t, router, http.MethodPost, "/api/v1/exceptions", excBody)
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())
	var createdExc map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &createdExc))
	excID, _ := createdExc["id"].(string)
	w = authedRequest(t, router, http.MethodPut, "/api/v1/exceptions/"+excID, excBody)
	require.Equal(t, http.StatusOK, w.Code)
	w = authedRequest(t, router, http.MethodDelete, "/api/v1/exceptions/"+excID, nil)
	require.Equal(t, http.StatusNoContent, w.Code)

	events := configChangeEvents(readAuditEvents(t, auditLogger, path))
	// All seven persisting mutations fired.
	require.Len(t, events, 7, "expected one ConfigurationChange per persisting mutation")
	for _, ev := range events {
		assert.NotEqual(t, "system:unauthenticated", ev.UserInfo.Username,
			"no persisting mutation may be attributed to system:unauthenticated when authN is enabled (verb=%s resource=%v)",
			ev.Operation, ev.Metadata["resource"])
		assert.Equal(t, "alice", ev.UserInfo.Username)
	}
}

// TestManagerAudit_DevFallbackLabelsUnauthenticated covers the dev-only posture
// (authN disabled): a mutation still emits an event, honestly labeled
// system:unauthenticated. The router does NOT mount OIDC/RBAC when
// authCfg.Enabled is false, so the request needs no token.
func TestManagerAudit_DevFallbackLabelsUnauthenticated(t *testing.T) {
	m := newTestManager(t)
	auditLogger, path := newFileAuditLogger(t)
	m.SetAuditLogger(auditLogger)

	disabledAuth := config.AuthConfig{Enabled: false}
	router := NewAPIRouter(m, disabledAuth, config.RBACConfig{}, nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", bytes.NewReader(policyBody(t, "dev")))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())

	events := configChangeEvents(readAuditEvents(t, auditLogger, path))
	require.Len(t, events, 1)
	assert.Equal(t, "CREATE", events[0].Operation)
	assert.Equal(t, "system:unauthenticated", events[0].UserInfo.Username,
		"with authN disabled, the mutation is honestly labeled system:unauthenticated")
	assert.Contains(t, events[0].UserInfo.Groups, "system:unauthenticated")
	// source_ip is still recorded.
	changes, ok := events[0].Metadata["changes"].(map[string]any)
	require.True(t, ok)
	assert.NotEmpty(t, changes["source_ip"])
}

// TestManagerAudit_PlaygroundRPCsEmitNoConfigChange asserts the non-persisting
// playground RPCs (/policies/evaluate and /policies/:id/test) emit NO
// ConfigurationChange event. The /test route needs a pre-existing policy, so it
// is created first (which DOES emit one CREATE event); the test asserts exactly
// that single CREATE and nothing from the two RPC calls.
func TestManagerAudit_PlaygroundRPCsEmitNoConfigChange(t *testing.T) {
	m := newTestManager(t)
	auditLogger, path := newFileAuditLogger(t)
	m.SetAuditLogger(auditLogger)

	verifier := newHermeticVerifier(t)
	router := NewAPIRouter(m, testAuthConfig(), auditTestRBAC(), verifier)

	// Seed a policy so /policies/:id/test resolves (this is the only persisting
	// call in this test → exactly one CREATE event).
	w := authedRequest(t, router, http.MethodPost, "/api/v1/policies", policyBody(t, "seed"))
	require.Equal(t, http.StatusCreated, w.Code, "body: %s", w.Body.String())
	var created map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &created))
	id, _ := created["id"].(string)
	require.NotEmpty(t, id)

	pod := map[string]any{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata":   map[string]any{"name": "x", "namespace": "default"},
	}
	podBytes, _ := json.Marshal(pod)

	// /policies/:id/test (viewer-allowed, non-persisting).
	w = authedRequest(t, router, http.MethodPost, "/api/v1/policies/"+id+"/test", podBytes)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	// /policies/evaluate (viewer-allowed, non-persisting).
	evalBody, _ := json.Marshal(map[string]any{
		"resource": pod,
		"policy": map[string]any{
			"name":  "inline",
			"rules": []map[string]any{{"name": "r1", "rego": validRego}},
		},
	})
	w = authedRequest(t, router, http.MethodPost, "/api/v1/policies/evaluate", evalBody)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())

	events := configChangeEvents(readAuditEvents(t, auditLogger, path))
	require.Len(t, events, 1, "only the seed CREATE should emit a ConfigurationChange; the two playground RPCs must emit none")
	assert.Equal(t, "CREATE", events[0].Operation)
	assert.Equal(t, "policy", events[0].Metadata["resource"])
}
