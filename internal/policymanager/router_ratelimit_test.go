package policymanager

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/Jibbscript/kube-policies/internal/config"
)

// TestAPIRouter_SSEStreamConnectionCap exercises the NET-WU-15 SSE connection
// gate end-to-end through the REAL NewAPIRouter: with MaxStreamConnections=1, a
// single authenticated /decisions/stream connection holds the only slot, the
// second concurrent stream is rejected with 429, and after the first
// disconnects the slot is released so a fresh stream succeeds.
//
// The static internal token authenticates the read feed via the
// authenticateServiceBearer static fallback (no TokenReview reviewer wired), so
// the gated handler is actually reached and holds its slot open.
func TestAPIRouter_SSEStreamConnectionCap(t *testing.T) {
	const token = "stream-cap-token"
	m := newTestManagerTokenized(t, token)

	rlCfg := config.RateLimitConfig{
		Enabled:              true,
		RequestsPerSecond:    1e6, // effectively unlimited so only the stream cap bites
		Burst:                100000,
		MaxConcurrent:        0, // disable general concurrency cap for this test
		MaxBodyBytes:         0,
		MaxStreamConnections: 1,
	}
	router := NewAPIRouter(m, config.AuthConfig{}, config.RBACConfig{}, nil, rlCfg, nil)

	srv := httptest.NewServer(router)
	defer srv.Close()

	streamURL := srv.URL + "/api/v1/decisions/stream"

	// openStream dials the stream with the given context and returns the HTTP
	// status once the response headers arrive. For a 200 it keeps the body open
	// (the caller cancels via ctx to release the slot).
	openStream := func(ctx context.Context) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, streamURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		return http.DefaultClient.Do(req)
	}

	// 1) First stream acquires the only slot and stays connected.
	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	resp1, err := openStream(ctx1)
	require.NoError(t, err)
	defer resp1.Body.Close()
	require.Equal(t, http.StatusOK, resp1.StatusCode)
	require.Equal(t, "text/event-stream", resp1.Header.Get("Content-Type"))

	// Confirm the handler is actually subscribed (slot is held inside StreamDecisions).
	require.Eventually(t, func() bool { return m.bus.NumSubscribers() == 1 },
		2*time.Second, 5*time.Millisecond, "first stream should be subscribed")

	// 2) Second concurrent stream must be rejected with 429 by the gate (which
	//    runs BEFORE auth, so no token round-trip is needed to be refused).
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	resp2, err := openStream(ctx2)
	require.NoError(t, err)
	defer resp2.Body.Close()
	assert.Equal(t, http.StatusTooManyRequests, resp2.StatusCode,
		"the 2nd concurrent SSE stream must be capped with 429")

	// 3) Disconnect the first stream; the gate slot must be released.
	cancel1()
	_ = resp1.Body.Close()
	require.Eventually(t, func() bool { return m.bus.NumSubscribers() == 0 },
		2*time.Second, 5*time.Millisecond, "slot/subscriber should be released on disconnect")

	// 4) A fresh stream now succeeds because the slot was freed.
	ctx3, cancel3 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel3()
	resp3, err := openStream(ctx3)
	require.NoError(t, err)
	defer resp3.Body.Close()
	assert.Equal(t, http.StatusOK, resp3.StatusCode,
		"a new stream must succeed after the capped slot is released")
}

// TestAPIRouter_RateLimit429 confirms the general request limiter is mounted on
// the management plane via NewAPIRouter: with a tiny burst and a near-zero
// refill, requests beyond the burst are rejected with 429.
func TestAPIRouter_RateLimit429(t *testing.T) {
	m := newTestManagerTokenized(t, "tok")
	rlCfg := config.RateLimitConfig{
		Enabled:           true,
		RequestsPerSecond: 0.001,
		Burst:             1,
	}
	// Auth disabled so the management route is reachable without an OIDC token;
	// the rate limiter runs regardless of auth.
	router := NewAPIRouter(m, config.AuthConfig{}, config.RBACConfig{}, nil, rlCfg, nil)
	srv := httptest.NewServer(router)
	defer srv.Close()

	url := srv.URL + "/api/v1/policies"
	var codes []int
	// Issue requests sequentially so the single burst token is consumed first.
	for i := 0; i < 3; i++ {
		resp, err := http.Get(url)
		require.NoError(t, err)
		codes = append(codes, resp.StatusCode)
		_ = resp.Body.Close()
	}

	assert.Equal(t, http.StatusOK, codes[0], "first request within burst should pass")
	// At least one of the subsequent requests must be 429.
	sawLimited := false
	for _, c := range codes[1:] {
		if c == http.StatusTooManyRequests {
			sawLimited = true
		}
	}
	assert.True(t, sawLimited, "a request beyond the burst must be 429; got %v", codes)
}
