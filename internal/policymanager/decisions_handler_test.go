package policymanager

import (
	"bytes"
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Jibbscript/kube-policies/internal/audit"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
