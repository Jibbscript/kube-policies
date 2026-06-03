package policymanager

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// dashboardSA is the dashboard ServiceAccount username the decisions-read
// reviewer is pinned to in these tests (mirrors the chart's
// POLICY_MANAGER_DECISIONS_READER_SUBJECT).
const dashboardSA = "system:serviceaccount:kube-policies:kube-policies-dashboard"

// setReadReviewerWithSubject installs the decisions-read TokenReview
// authenticator on m, pinned to expectedUsername, driven by react. This mirrors
// setReviewerReactorWithSubject (decisions_handler_test.go) but targets the read
// side (SetDecisionsReadAuthenticator) — the dashboard-SA pin — not /internal.
func setReadReviewerWithSubject(m *Manager, audience, expectedUsername string, react func() (runtime.Object, error)) {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "tokenreviews", func(clienttesting.Action) (bool, runtime.Object, error) {
		obj, err := react()
		return true, obj, err
	})
	m.SetDecisionsReadAuthenticator(NewInternalTokenAuthenticator(cs.AuthenticationV1().TokenReviews(), audience, expectedUsername, zap.NewNop()))
}

// reviewAuthenticatedAs returns a reactor result for an authenticated token
// bound to audiences and asserting the given username.
func reviewAuthenticatedAs(username string, audiences ...string) func() (runtime.Object, error) {
	return func() (runtime.Object, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				Audiences:     audiences,
				User:          authenticationv1.UserInfo{Username: username},
			},
		}, nil
	}
}

// doReadRequest serves GET path through the real NewAPIRouter (so the
// DecisionsReadAuth middleware runs exactly as in production) with the given
// bearer and returns the recorder. A management OIDC verifier is wired so the
// router matches production; the decisions group is OIDC-exempt regardless.
func doReadRequest(t *testing.T, m *Manager, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	v := newHermeticVerifier(t)
	router := NewAPIRouter(m, testAuthConfig(), rbacTestConfig(), v, config.RateLimitConfig{}, nil)
	req := httptest.NewRequest(http.MethodGet, path, strings.NewReader(""))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// TestDecisionsRead_TokenReview_DashboardSA_Accepted proves a valid
// audience-bound token from the DASHBOARD SA passes the read middleware and the
// handler runs (200 from /recent).
func TestDecisionsRead_TokenReview_DashboardSA_Accepted(t *testing.T) {
	m := newTestManagerTokenized(t, "") // no static fallback configured
	setReadReviewerWithSubject(m, "policy-manager", dashboardSA,
		reviewAuthenticatedAs(dashboardSA, "policy-manager"))

	w := doReadRequest(t, m, "/api/v1/decisions/recent", "dashboard-projected-token")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"degraded"`)
}

// TestDecisionsRead_TokenReview_WrongSubject_401 proves a valid audience-bound
// token from the WRONG SA (e.g. the webhook SA, or a random SA) is rejected when
// the read reviewer is subject-pinned to the dashboard SA.
func TestDecisionsRead_TokenReview_WrongSubject_401(t *testing.T) {
	for _, wrong := range []string{
		"system:serviceaccount:kube-policies:admission-webhook", // webhook SA
		"system:serviceaccount:default:other-sa",                // random SA
	} {
		t.Run(wrong, func(t *testing.T) {
			m := newTestManagerTokenized(t, "")
			setReadReviewerWithSubject(m, "policy-manager", dashboardSA,
				reviewAuthenticatedAs(wrong, "policy-manager"))

			w := doReadRequest(t, m, "/api/v1/decisions/recent", "wrong-sa-token")
			assert.Equal(t, http.StatusUnauthorized, w.Code,
				"correct audience but wrong subject must be rejected by the read pin")
		})
	}
}

// TestDecisionsRead_TokenReview_APIError_401_FailClosed proves the fail-closed
// guarantee for the reads: a TokenReview API error rejects with 401 and never
// falls through to a configured static token.
func TestDecisionsRead_TokenReview_APIError_401_FailClosed(t *testing.T) {
	m := newTestManagerTokenized(t, "static-fallback-token") // static IS configured
	setReadReviewerWithSubject(m, "policy-manager", dashboardSA, func() (runtime.Object, error) {
		return nil, errors.New("apiserver unreachable")
	})

	// Present the static token, which WOULD pass if we fell through. Still 401.
	w := doReadRequest(t, m, "/api/v1/decisions/recent", "static-fallback-token")
	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"a TokenReview API error on the reads must fail closed, never fall through to static")
}

// TestDecisionsRead_StaticFallback_WhenNoReviewer proves static mode: with no
// read reviewer installed, a correct static token passes the read middleware.
func TestDecisionsRead_StaticFallback_WhenNoReviewer(t *testing.T) {
	m := newTestManagerTokenized(t, "static-token") // no read reviewer installed
	w := doReadRequest(t, m, "/api/v1/decisions/recent", "static-token")
	require.Equal(t, http.StatusOK, w.Code)
}

// TestDecisionsRead_StaticFallback_WrongToken_401 proves a wrong static token is
// rejected in static mode.
func TestDecisionsRead_StaticFallback_WrongToken_401(t *testing.T) {
	m := newTestManagerTokenized(t, "correct-token")
	w := doReadRequest(t, m, "/api/v1/decisions/recent", "wrong-token")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestDecisionsRead_CleanNegative_FallsToStatic proves a clean negative
// TokenReview verdict falls through to a valid static token (static fallback in
// tokenreview mode), exactly like /internal.
func TestDecisionsRead_CleanNegative_FallsToStatic(t *testing.T) {
	m := newTestManagerTokenized(t, "static-token")
	setReadReviewerWithSubject(m, "policy-manager", dashboardSA, func() (runtime.Object, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{Authenticated: false},
		}, nil
	})
	w := doReadRequest(t, m, "/api/v1/decisions/recent", "static-token")
	require.Equal(t, http.StatusOK, w.Code,
		"a clean negative read verdict should fall through to a valid static token")
}

// TestDecisionsRead_NoToken_401 proves an unauthenticated read is rejected even
// when nothing is configured (an empty verifier is not a wildcard).
func TestDecisionsRead_NoToken_401(t *testing.T) {
	m := newTestManagerTokenized(t, "") // nothing configured
	w := doReadRequest(t, m, "/api/v1/decisions/recent", "")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestDecisionsRead_EmptyBearer_ShortCircuitsBeforeReviewer proves an empty
// Authorization header 401s BEFORE the read TokenReview reactor is invoked.
func TestDecisionsRead_EmptyBearer_ShortCircuitsBeforeReviewer(t *testing.T) {
	reactorCalled := false
	m := newTestManagerTokenized(t, "static-token")
	cs := fake.NewClientset()
	cs.PrependReactor("create", "tokenreviews", func(clienttesting.Action) (bool, runtime.Object, error) {
		reactorCalled = true
		return true, &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{Authenticated: true, Audiences: []string{"policy-manager"}},
		}, nil
	})
	m.SetDecisionsReadAuthenticator(NewInternalTokenAuthenticator(cs.AuthenticationV1().TokenReviews(), "policy-manager", dashboardSA, zap.NewNop()))

	w := doReadRequest(t, m, "/api/v1/decisions/recent", "") // empty Authorization
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, reactorCalled, "the read TokenReview reactor must NOT run on an empty Authorization header")
}

// TestDecisionsRead_StreamRouteGuarded confirms the SAME middleware guards
// /decisions/stream (not just /recent): no token => 401 before the SSE handler
// hijacks the connection.
func TestDecisionsRead_StreamRouteGuarded(t *testing.T) {
	m := newTestManagerTokenized(t, "static-token")
	w := doReadRequest(t, m, "/api/v1/decisions/stream", "wrong-token")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestDecisionsRead_InternalPinUnchanged proves Inc7 did NOT weaken /internal:
// the ingest endpoint still rejects the dashboard SA (it is pinned to the
// webhook SA), even though the dashboard SA is accepted on the reads. This
// guards against the two reviewers being accidentally collapsed.
func TestDecisionsRead_InternalPinUnchanged(t *testing.T) {
	m := newTestManagerTokenized(t, "")
	// /internal pinned to the webhook SA.
	setReviewerReactorWithSubject(m, "policy-manager", "system:serviceaccount:kube-policies:admission-webhook",
		reviewAuthenticatedAs(dashboardSA, "policy-manager")) // token is the DASHBOARD SA

	body := []byte(`{"decision":"ALLOW","kind":"Pod"}`)
	w := doIngestRequest(t, m, "dashboard-token-on-internal", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"the dashboard SA must NOT be accepted on /internal (webhook-SA pin must stay intact)")
}
