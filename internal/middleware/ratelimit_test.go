package middleware

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() { gin.SetMode(gin.TestMode) }

// fakeMetrics records IncRateLimited calls so tests can assert the metric is
// incremented with the expected labels. Safe for concurrent use.
type fakeMetrics struct {
	mu    sync.Mutex
	calls [][2]string // {handler, reason}
}

func (f *fakeMetrics) IncRateLimited(handler, reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, [2]string{handler, reason})
}

func (f *fakeMetrics) countReason(reason string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if c[1] == reason {
			n++
		}
	}
	return n
}

func (f *fakeMetrics) total() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// newEngine mounts the limiter on a single OK handler at /test, registering a
// /healthz route BEFORE the middleware to prove health bypasses the limiter.
func newEngine(rl *RateLimiter) *gin.Engine {
	r := gin.New()
	r.GET("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.POST("/healthz", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	grp := r.Group("", rl.RequestMiddleware())
	grp.POST("/test", func(c *gin.Context) {
		// Read the (possibly MaxBytesReader-wrapped) body. A correct handler maps
		// a *http.MaxBytesError to 413 — mirrors how the production handlers
		// should surface an oversized body capped by the middleware.
		if _, err := io.ReadAll(c.Request.Body); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				c.String(http.StatusRequestEntityTooLarge, "body too large")
				return
			}
			c.String(http.StatusBadRequest, "bad body")
			return
		}
		c.String(http.StatusOK, "ok")
	})
	grp.GET("/test", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

func TestRateLimiter_Disabled_PassThrough(t *testing.T) {
	fm := &fakeMetrics{}
	rl := New(Config{Enabled: false, RequestsPerSecond: 1, Burst: 1, MaxConcurrent: 1, MaxBodyBytes: 1}, fm)
	r := newEngine(rl)

	// Many requests, all should pass: the middleware is a no-op when disabled.
	for i := 0; i < 50; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	}
	assert.Equal(t, 0, fm.total(), "disabled limiter must not record any rejection")
}

func TestRateLimiter_RateExceeded_429(t *testing.T) {
	fm := &fakeMetrics{}
	// Burst of 2, very slow refill so the 3rd immediate request is refused.
	rl := New(Config{Enabled: true, RequestsPerSecond: 0.001, Burst: 2}, fm)
	r := newEngine(rl)

	codes := make([]int, 0, 3)
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		r.ServeHTTP(w, req)
		codes = append(codes, w.Code)
	}
	assert.Equal(t, http.StatusOK, codes[0])
	assert.Equal(t, http.StatusOK, codes[1])
	assert.Equal(t, http.StatusTooManyRequests, codes[2], "3rd request beyond burst must be 429")
	assert.Equal(t, 1, fm.countReason(ReasonRate))
	// The handler label is the matched route template.
	fm.mu.Lock()
	require.NotEmpty(t, fm.calls)
	assert.Equal(t, "/test", fm.calls[0][0])
	fm.mu.Unlock()
}

func TestRateLimiter_ConcurrencyExceeded_429(t *testing.T) {
	fm := &fakeMetrics{}
	// High rate so the rate limiter never trips; concurrency cap of 1.
	rl := New(Config{Enabled: true, RequestsPerSecond: 1e6, Burst: 1000, MaxConcurrent: 1}, fm)

	// A handler that blocks until released so we can hold the single slot.
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	r := gin.New()
	grp := r.Group("", rl.RequestMiddleware())
	grp.GET("/test", func(c *gin.Context) {
		entered <- struct{}{}
		<-release
		c.String(http.StatusOK, "ok")
	})

	// First request holds the slot.
	var firstCode int32
	go func() {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		r.ServeHTTP(w, req)
		atomic.StoreInt32(&firstCode, int32(w.Code))
	}()
	<-entered // first request is now inside the handler holding the slot

	// Second concurrent request must be rejected (slot full, non-blocking).
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusTooManyRequests, w2.Code)
	assert.Equal(t, 1, fm.countReason(ReasonConcurrency))

	// Release the first; it should complete 200 and free the slot.
	close(release)
	require.Eventually(t, func() bool {
		return atomic.LoadInt32(&firstCode) == http.StatusOK
	}, time.Second, 5*time.Millisecond)

	// With the slot freed, a new request (which will block in the handler again
	// after acquiring) reaches the handler — confirmed by a fresh `entered`
	// signal — proving the slot was released rather than leaked.
	go func() {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		// The handler reads from the already-closed `release`, so it returns
		// immediately; we only need it to enter to prove the freed slot is reusable.
		r.ServeHTTP(w, req)
	}()
	select {
	case <-entered:
		// Acquired the freed slot and entered the handler — slot was released.
	case <-time.After(time.Second):
		t.Fatal("freed concurrency slot was not reusable")
	}
	assert.Equal(t, 1, fm.countReason(ReasonConcurrency), "no extra concurrency rejection after slot freed")
}

func TestRateLimiter_BodyTooLarge_413_DeclaredContentLength(t *testing.T) {
	fm := &fakeMetrics{}
	rl := New(Config{Enabled: true, RequestsPerSecond: 1e6, Burst: 1000, MaxBodyBytes: 16}, fm)
	r := newEngine(rl)

	body := bytes.Repeat([]byte("x"), 64) // declared Content-Length 64 > 16
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
	assert.Equal(t, 1, fm.countReason(ReasonBodyTooLarge))
}

func TestRateLimiter_BodyTooLarge_413_Chunked(t *testing.T) {
	fm := &fakeMetrics{}
	rl := New(Config{Enabled: true, RequestsPerSecond: 1e6, Burst: 1000, MaxBodyBytes: 16}, fm)
	r := newEngine(rl)

	// ContentLength = -1 (chunked/unknown): the eager check is skipped, so the
	// 413 must come from MaxBytesReader when the handler reads past the cap.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", strings.NewReader(strings.Repeat("y", 64)))
	req.ContentLength = -1
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code,
		"oversized chunked body must trip MaxBytesReader -> 413")
}

func TestRateLimiter_UnderLimits_OK(t *testing.T) {
	fm := &fakeMetrics{}
	rl := New(Config{Enabled: true, RequestsPerSecond: 1e6, Burst: 1000, MaxConcurrent: 10, MaxBodyBytes: 1 << 20}, fm)
	r := newEngine(rl)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("small")))
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, 0, fm.total())
}

func TestRateLimiter_HealthBypasses(t *testing.T) {
	fm := &fakeMetrics{}
	// Rate limiter that would reject everything after the first burst token.
	rl := New(Config{Enabled: true, RequestsPerSecond: 0.001, Burst: 1}, fm)
	r := newEngine(rl) // /healthz registered before the limited group

	// Hammer /healthz far beyond the burst — it must never be throttled.
	for i := 0; i < 20; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code, "health probe must never be rate-limited")
	}
	assert.Equal(t, 0, fm.total())
}

func TestRateLimiter_NilMetrics_NoPanic(t *testing.T) {
	rl := New(Config{Enabled: true, RequestsPerSecond: 0.001, Burst: 1}, nil)
	r := newEngine(rl)

	// Second request 429s; with nil metrics it must not panic.
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		r.ServeHTTP(w, req)
	}
}

// --- StreamGate (NET-WU-15) ---

func TestStreamGate_CapAndRelease(t *testing.T) {
	fm := &fakeMetrics{}
	const maxStreams = 2
	gate := NewStreamGate(maxStreams, "/stream", fm)

	release := make(chan struct{})
	entered := make(chan struct{}, maxStreams)
	r := gin.New()
	r.GET("/stream", gate.Middleware(), func(c *gin.Context) {
		entered <- struct{}{}
		<-release
		c.String(http.StatusOK, "done")
	})

	// Open maxStreams concurrent connections; each holds its slot.
	done := make(chan int, maxStreams)
	for i := 0; i < maxStreams; i++ {
		go func() {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/stream", nil)
			r.ServeHTTP(w, req)
			done <- w.Code
		}()
	}
	for i := 0; i < maxStreams; i++ {
		<-entered // all maxStreams handlers are now in-flight holding slots
	}
	assert.Equal(t, int64(maxStreams), gate.Active())

	// The N+1th concurrent connection must be rejected with 429.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/stream", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, 1, fm.countReason(ReasonStreamCapacity))
	fm.mu.Lock()
	assert.Equal(t, "/stream", fm.calls[0][0])
	fm.mu.Unlock()

	// Release the held connections; slots free up.
	close(release)
	for i := 0; i < maxStreams; i++ {
		assert.Equal(t, http.StatusOK, <-done)
	}
	require.Eventually(t, func() bool { return gate.Active() == 0 }, time.Second, 5*time.Millisecond)

	// A new connection now succeeds because a slot was released on disconnect.
	relisten := make(chan struct{})
	close(relisten)
	r2 := gin.New()
	r2.GET("/stream", gate.Middleware(), func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/stream", nil)
	r2.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code, "slot must be reusable after disconnect")
}

func TestStreamGate_Disabled_PassThrough(t *testing.T) {
	fm := &fakeMetrics{}
	gate := NewStreamGate(0, "/stream", fm) // 0 => disabled
	r := gin.New()
	r.GET("/stream", gate.Middleware(), func(c *gin.Context) { c.String(http.StatusOK, "ok") })

	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/stream", nil)
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusOK, w.Code)
	}
	assert.Equal(t, 0, fm.total())
}

func TestStreamGate_NilSafe(t *testing.T) {
	var gate *StreamGate
	// nil gate Middleware is a pass-through and Active is 0.
	mw := gate.Middleware()
	r := gin.New()
	r.GET("/stream", mw, func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/stream", nil)
	r.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, int64(0), gate.Active())
}

// TestStreamGate_RaceUnderLoad exercises the gate under concurrent acquire /
// release to confirm -race cleanliness of the atomic counter.
func TestStreamGate_RaceUnderLoad(t *testing.T) {
	gate := NewStreamGate(8, "/stream", nil)
	r := gin.New()
	r.GET("/stream", gate.Middleware(), func(c *gin.Context) {
		time.Sleep(time.Millisecond)
		c.String(http.StatusOK, "ok")
	})
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/stream", nil)
			r.ServeHTTP(w, req)
			// Either admitted (200) or capped (429); both are valid under load.
			if w.Code != http.StatusOK && w.Code != http.StatusTooManyRequests {
				t.Errorf("unexpected status %d", w.Code)
			}
		}()
	}
	wg.Wait()
	require.Eventually(t, func() bool { return gate.Active() == 0 }, time.Second, 5*time.Millisecond)
}
