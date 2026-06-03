package policymanager

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"

	"github.com/Jibbscript/kube-policies/internal/audit"
	"github.com/Jibbscript/kube-policies/internal/policy"
)

// setReviewerReactor installs a TokenReview authenticator on m whose fake
// "create tokenreviews" reactor is driven by react, exercising the IAM-WU-11
// validation path with no real apiserver. expectedUsername "" disables subject
// pinning; pass the webhook SA name to exercise the subject-pin path.
func setReviewerReactor(m *Manager, audience string, react func() (runtime.Object, error)) {
	setReviewerReactorWithSubject(m, audience, "", react)
}

func setReviewerReactorWithSubject(m *Manager, audience, expectedUsername string, react func() (runtime.Object, error)) {
	cs := fake.NewClientset()
	cs.PrependReactor("create", "tokenreviews", func(clienttesting.Action) (bool, runtime.Object, error) {
		obj, err := react()
		return true, obj, err
	})
	m.SetInternalTokenReviewer(NewInternalTokenAuthenticator(cs.AuthenticationV1().TokenReviews(), audience, expectedUsername, zap.NewNop()))
}

// reviewAuthenticated returns a reactor result for an authenticated token bound
// to the given audiences.
func reviewAuthenticated(audiences ...string) func() (runtime.Object, error) {
	return func() (runtime.Object, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{
				Authenticated: true,
				Audiences:     audiences,
				User:          authenticationv1.UserInfo{Username: "system:serviceaccount:kube-policies:admission-webhook"},
			},
		}, nil
	}
}

// --- IngestInternal TokenReview (IAM-WU-11) tests ---

func TestIngestInternal_TokenReview_Accepted_204(t *testing.T) {
	m := newTestManagerTokenized(t, "") // no static token configured
	setReviewerReactor(m, "policy-manager", reviewAuthenticated("policy-manager"))

	body, _ := json.Marshal(audit.PublicEvent{Decision: "ALLOW", Kind: "Pod"})
	w := doIngestRequest(t, m, "valid-projected-token", body)
	require.Equal(t, http.StatusNoContent, w.Code)

	recent := m.recentRing.Recent(1)
	require.Len(t, recent, 1)
	assert.Equal(t, "ALLOW", recent[0].Decision)
}

func TestIngestInternal_TokenReview_GenericSA_401(t *testing.T) {
	m := newTestManagerTokenized(t, "") // no static fallback
	// Authenticated but wrong audience: a generic SA token must NOT be admitted.
	setReviewerReactor(m, "policy-manager", reviewAuthenticated("https://kubernetes.default.svc"))

	body, _ := json.Marshal(audit.PublicEvent{Decision: "ALLOW", Kind: "Pod"})
	w := doIngestRequest(t, m, "generic-sa-token", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestIngestInternal_TokenReview_APIError_401_FailClosed proves the fail-closed
// guarantee: when the TokenReview API errors AND a static token is also
// configured, the request is still rejected — there is NO fall-through to static
// on an API error.
func TestIngestInternal_TokenReview_APIError_401_FailClosed(t *testing.T) {
	m := newTestManagerTokenized(t, "static-fallback-token") // static IS configured
	setReviewerReactor(m, "policy-manager", func() (runtime.Object, error) {
		return nil, errors.New("apiserver unreachable")
	})

	// Present the static token, which WOULD pass the static path if we fell
	// through. We must still get 401.
	body, _ := json.Marshal(audit.PublicEvent{Decision: "ALLOW", Kind: "Pod"})
	w := doIngestRequest(t, m, "static-fallback-token", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"a TokenReview API error must fail closed and never fall through to the static path")
}

// TestIngestInternal_StaticFallback_WhenNoReviewer_204 proves backward
// compatibility: with no reviewer set, the static path behaves exactly as before.
func TestIngestInternal_StaticFallback_WhenNoReviewer_204(t *testing.T) {
	m := newTestManagerTokenized(t, "static-token") // no reviewer installed
	body, _ := json.Marshal(audit.PublicEvent{Decision: "DENY", Kind: "Pod"})
	w := doIngestRequest(t, m, "static-token", body)
	require.Equal(t, http.StatusNoContent, w.Code)
}

// TestIngestInternal_TokenReviewPrecedenceOverStatic proves a valid
// audience-bound TokenReview verdict admits the request even when the presented
// token is NOT the configured static token — the TokenReview path takes
// precedence and the static comparison is never reached.
func TestIngestInternal_TokenReviewPrecedenceOverStatic(t *testing.T) {
	m := newTestManagerTokenized(t, "some-other-static-token")
	setReviewerReactor(m, "policy-manager", reviewAuthenticated("policy-manager"))

	body, _ := json.Marshal(audit.PublicEvent{Decision: "ALLOW", Kind: "Pod"})
	// Token is neither empty nor the static token, but TokenReview accepts it.
	w := doIngestRequest(t, m, "projected-token-not-matching-static", body)
	require.Equal(t, http.StatusNoContent, w.Code)
}

// TestIngestInternal_TokenReviewCleanNegative_FallsToStatic proves a CLEAN
// negative verdict (err==nil, ok==false) falls through to the static path, which
// then accepts the correct static token.
func TestIngestInternal_TokenReviewCleanNegative_FallsToStatic(t *testing.T) {
	m := newTestManagerTokenized(t, "static-token")
	// Clean negative: not authenticated. No API error -> may fall through.
	setReviewerReactor(m, "policy-manager", func() (runtime.Object, error) {
		return &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{Authenticated: false},
		}, nil
	})

	body, _ := json.Marshal(audit.PublicEvent{Decision: "ALLOW", Kind: "Pod"})
	w := doIngestRequest(t, m, "static-token", body)
	require.Equal(t, http.StatusNoContent, w.Code,
		"a clean negative TokenReview verdict should fall through to a valid static token")
}

// TestIngestInternal_EmptyBearer_ShortCircuitsBeforeReviewer proves (FIX 9a)
// that an empty Authorization header returns 401 BEFORE the TokenReview reactor
// is ever invoked — the empty-bearer short-circuit in IngestInternal must
// precede the reviewer call.
func TestIngestInternal_EmptyBearer_ShortCircuitsBeforeReviewer(t *testing.T) {
	reactorCalled := false
	m := newTestManagerTokenized(t, "static-token")
	cs := fake.NewClientset()
	cs.PrependReactor("create", "tokenreviews", func(clienttesting.Action) (bool, runtime.Object, error) {
		reactorCalled = true
		return true, &authenticationv1.TokenReview{
			Status: authenticationv1.TokenReviewStatus{Authenticated: true, Audiences: []string{"policy-manager"}},
		}, nil
	})
	m.SetInternalTokenReviewer(NewInternalTokenAuthenticator(cs.AuthenticationV1().TokenReviews(), "policy-manager", "", zap.NewNop()))

	body, _ := json.Marshal(audit.PublicEvent{Decision: "ALLOW", Kind: "Pod"})
	w := doIngestRequest(t, m, "", body) // empty Authorization header
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.False(t, reactorCalled, "the TokenReview reactor must NOT be invoked when the Authorization header is empty")
}

// TestIngestInternal_SubjectPin_WrongSA_401 proves (FIX 3) that a valid
// audience-bound token from the WRONG ServiceAccount is rejected by the handler
// when subject pinning is configured.
func TestIngestInternal_SubjectPin_WrongSA_401(t *testing.T) {
	m := newTestManagerTokenized(t, "")
	setReviewerReactorWithSubject(m, "policy-manager", "system:serviceaccount:kube-policies:admission-webhook",
		func() (runtime.Object, error) {
			return &authenticationv1.TokenReview{
				Status: authenticationv1.TokenReviewStatus{
					Authenticated: true,
					Audiences:     []string{"policy-manager"},
					// Different SA — correct audience but wrong subject.
					User: authenticationv1.UserInfo{Username: "system:serviceaccount:default:other-sa"},
				},
			}, nil
		})

	body, _ := json.Marshal(audit.PublicEvent{Decision: "ALLOW", Kind: "Pod"})
	w := doIngestRequest(t, m, "other-sa-projected-token", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code,
		"correct audience but wrong subject must be rejected when subject pinning is enabled")
}

// init() for gin.TestMode is already declared in test_handler_test.go.

// newTestManagerTokenized creates a Manager with the given internal token set.
func newTestManagerTokenized(t *testing.T, token string) *Manager {
	t.Helper()
	m := newTestManagerWithPolicy(t, nil)
	m.SetInternalToken(token)
	return m
}

// doIngestRequest sends a POST /api/v1/decisions/internal with the given
// bearer token and body, returning the recorded response.
func doIngestRequest(t *testing.T, m *Manager, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/decisions/internal", bytes.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	c.Request = req
	m.IngestInternal(c)
	return w
}

// --- IngestInternal tests ---

func TestIngestInternal_EmptyTokenAlways401(t *testing.T) {
	m := newTestManagerTokenized(t, "") // token not configured
	body, _ := json.Marshal(audit.PublicEvent{Decision: "ALLOW", Kind: "Pod"})
	w := doIngestRequest(t, m, "any-token", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestIngestInternal_WrongToken401(t *testing.T) {
	m := newTestManagerTokenized(t, "correct-token")
	body, _ := json.Marshal(audit.PublicEvent{Decision: "ALLOW", Kind: "Pod"})
	w := doIngestRequest(t, m, "wrong-token", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestIngestInternal_MissingAuthHeader401(t *testing.T) {
	m := newTestManagerTokenized(t, "correct-token")
	body, _ := json.Marshal(audit.PublicEvent{Decision: "ALLOW", Kind: "Pod"})
	w := doIngestRequest(t, m, "", body) // no Authorization header
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestIngestInternal_BadBody400(t *testing.T) {
	m := newTestManagerTokenized(t, "tok")
	w := doIngestRequest(t, m, "tok", []byte("{not json"))
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestIngestInternal_MissingDecision400(t *testing.T) {
	m := newTestManagerTokenized(t, "tok")
	body, _ := json.Marshal(audit.PublicEvent{Kind: "Pod"}) // Decision is empty
	w := doIngestRequest(t, m, "tok", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestIngestInternal_Success204_RingAndBus(t *testing.T) {
	m := newTestManagerTokenized(t, "tok")

	// Subscribe before ingesting so we can assert the bus delivery.
	ch, cancel := m.bus.Subscribe()
	defer cancel()

	ev := audit.PublicEvent{Decision: "DENY", Kind: "Pod", RuleID: "no-priv", PolicyID: "sec"}
	body, _ := json.Marshal(ev)
	w := doIngestRequest(t, m, "tok", body)
	require.Equal(t, http.StatusNoContent, w.Code)

	// Event must appear in the ring.
	recent := m.recentRing.Recent(1)
	require.Len(t, recent, 1)
	assert.Equal(t, "DENY", recent[0].Decision)
	assert.Equal(t, "no-priv", recent[0].RuleID)

	// Event must have been published to the bus.
	select {
	case received := <-ch:
		assert.Equal(t, "DENY", received.Decision)
	case <-time.After(time.Second):
		t.Fatal("timeout: event not received on bus channel")
	}
}

func TestIngestInternal_ZeroTimestampBackfilled(t *testing.T) {
	m := newTestManagerTokenized(t, "tok")
	ev := audit.PublicEvent{Decision: "ALLOW", Kind: "ConfigMap"} // zero Timestamp
	body, _ := json.Marshal(ev)
	before := time.Now()
	w := doIngestRequest(t, m, "tok", body)
	after := time.Now()
	require.Equal(t, http.StatusNoContent, w.Code)

	recent := m.recentRing.Recent(1)
	require.Len(t, recent, 1)
	ts := recent[0].Timestamp
	assert.False(t, ts.IsZero(), "timestamp should be backfilled")
	assert.True(t, !ts.Before(before.Add(-time.Second)) && !ts.After(after.Add(time.Second)),
		"backfilled timestamp %v not in expected range [%v, %v]", ts, before, after)
}

// TestIngestInternal_SuppressedByRoundTrip verifies the additive `suppressed_by`
// field on PublicEvent round-trips through the lenient decoder and lands in the
// recent-decisions ring intact. Anchors the lenient-decode comment in
// decisions_handler.go (plan §5.9.b) — future strict-decode changes break this
// test loudly instead of silently dropping audit records.
func TestIngestInternal_SuppressedByRoundTrip(t *testing.T) {
	m := newTestManagerTokenized(t, "tok")
	ev := audit.PublicEvent{
		Decision: "ALLOW",
		Kind:     "Pod",
		SuppressedBy: []policy.ExceptionRef{
			{ID: "exc-1", Name: "team-a-allow-privileged", PolicyID: "security-baseline", RuleID: "no-privileged-containers", Justification: "incident #42"},
			{ID: "exc-2", Name: "team-a-allow-hostpath", PolicyID: "security-baseline", RuleID: "no-host-path-volumes"},
		},
	}
	body, err := json.Marshal(ev)
	require.NoError(t, err)

	w := doIngestRequest(t, m, "tok", body)
	require.Equal(t, http.StatusNoContent, w.Code)

	recent := m.recentRing.Recent(1)
	require.Len(t, recent, 1)
	require.Len(t, recent[0].SuppressedBy, 2)
	assert.Equal(t, "exc-1", recent[0].SuppressedBy[0].ID)
	assert.Equal(t, "team-a-allow-privileged", recent[0].SuppressedBy[0].Name)
	assert.Equal(t, "security-baseline", recent[0].SuppressedBy[0].PolicyID)
	assert.Equal(t, "no-privileged-containers", recent[0].SuppressedBy[0].RuleID)
	assert.Equal(t, "incident #42", recent[0].SuppressedBy[0].Justification)
	assert.Equal(t, "exc-2", recent[0].SuppressedBy[1].ID)
}

// --- RecentDecisions tests ---

func TestRecentDecisions_EmptyRing_Degraded(t *testing.T) {
	m := newTestManagerTokenized(t, "tok")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/decisions/recent", nil)
	m.RecentDecisions(c)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Decisions []audit.PublicEvent `json:"decisions"`
		Degraded  bool                `json:"degraded"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Degraded)
	assert.Empty(t, resp.Decisions)
}

func TestRecentDecisions_AfterIngests_NewestFirst(t *testing.T) {
	m := newTestManagerTokenized(t, "tok")

	// Ingest A, B, C in order.
	for _, dec := range []string{"A", "B", "C"} {
		body, _ := json.Marshal(audit.PublicEvent{Decision: dec, Kind: "Pod"})
		w := doIngestRequest(t, m, "tok", body)
		require.Equal(t, http.StatusNoContent, w.Code)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/decisions/recent?limit=3", nil)
	m.RecentDecisions(c)

	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Decisions []audit.PublicEvent `json:"decisions"`
		Degraded  bool                `json:"degraded"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Degraded)
	require.Len(t, resp.Decisions, 3)
	// Newest-first: C, B, A.
	assert.Equal(t, "C", resp.Decisions[0].Decision)
	assert.Equal(t, "B", resp.Decisions[1].Decision)
	assert.Equal(t, "A", resp.Decisions[2].Decision)
}

func TestRecentDecisions_LimitClamped(t *testing.T) {
	m := newTestManagerTokenized(t, "tok")

	// Ingest 5 events.
	for i := 0; i < 5; i++ {
		body, _ := json.Marshal(audit.PublicEvent{Decision: "ALLOW", Kind: "Pod"})
		doIngestRequest(t, m, "tok", body)
	}

	// limit=2 should return only 2.
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/decisions/recent?limit=2", nil)
	m.RecentDecisions(c)
	require.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		Decisions []audit.PublicEvent `json:"decisions"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Decisions, 2)
}

// --- StreamDecisions tests ---

func TestStreamDecisions_ReceivesEvent(t *testing.T) {
	m := newTestManagerTokenized(t, "tok")

	// Use httptest.NewServer so the response writer supports http.Flusher properly.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, _ := gin.CreateTestContext(w)
		c.Request = r
		m.StreamDecisions(c)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, "text/event-stream", resp.Header.Get("Content-Type"))

	// Publish an event after a brief delay to allow the subscriber to register.
	go func() {
		// Poll until subscriber is registered (avoids fixed sleep).
		for i := 0; i < 200 && m.bus.NumSubscribers() == 0; i++ {
			time.Sleep(time.Millisecond)
		}
		m.bus.Publish(audit.PublicEvent{
			Decision:  "ALLOW",
			Kind:      "Pod",
			Timestamp: time.Now(),
		})
	}()

	// Scan lines until we find a data: line, then cancel.
	scanner := bufio.NewScanner(resp.Body)
	var found bool
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			found = true
			data := strings.TrimPrefix(line, "data: ")
			var ev audit.PublicEvent
			require.NoError(t, json.Unmarshal([]byte(data), &ev))
			assert.Equal(t, "ALLOW", ev.Decision)
			cancel() // disconnect client → handler returns
			break
		}
	}
	assert.True(t, found, "expected at least one SSE data: line")
}

func TestStreamDecisions_ExitsOnContextCancel(t *testing.T) {
	m := newTestManagerTokenized(t, "tok")

	w := httptest.NewRecorder()
	ctx, cancel := context.WithCancel(context.Background())

	req := httptest.NewRequest(http.MethodGet, "/api/v1/decisions/stream", nil).WithContext(ctx)
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	done := make(chan struct{})
	go func() {
		defer close(done)
		m.StreamDecisions(c)
	}()

	// Let the goroutine reach the select.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// StreamDecisions exited cleanly.
	case <-time.After(2 * time.Second):
		t.Fatal("StreamDecisions goroutine did not exit after context cancellation")
	}
}
