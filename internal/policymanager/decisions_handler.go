package policymanager

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/audit"
	"github.com/Jibbscript/kube-policies/internal/auth"
)

// IngestInternal handles POST /api/v1/decisions/internal.
//
// Auth (IAM-WU-11): the inbound Authorization: Bearer <token> is authenticated
// in one of two ways, in priority order:
//
//  1. Audience-bound TokenReview (primary, when SetInternalTokenReviewer was
//     called): the token is submitted to the Kubernetes TokenReview API bound to
//     the expected audience. A TokenReview API error FAILS CLOSED — the request
//     is rejected with 401 and never falls through to the static path, so a
//     transient apiserver outage cannot widen what is admitted. A valid,
//     correct-audience verdict admits the request.
//  2. Static shared bearer (fallback, opt-in for non-cluster/demo deployments):
//     reached only on a CLEAN negative TokenReview verdict (token not
//     authenticated / wrong audience), or when no reviewer is configured. The
//     presented token is compared against the configured token(s) in constant
//     time over fixed-length digests so neither contents nor length leak via
//     timing (CRY-WU-13, IAM-WU-07). An unconfigured verifier returns 401 — an
//     empty token must not act as a wildcard.
//
// Token material is never logged; only verdicts/usernames/errors are.
func (m *Manager) IngestInternal(c *gin.Context) {
	raw := auth.BearerToken(c.GetHeader("Authorization"))
	if raw == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "missing bearer token",
		})
		return
	}

	if m.internalReviewer != nil {
		ok, _, err := m.internalReviewer.Authenticate(c.Request.Context(), raw)
		if err != nil {
			// FAIL CLOSED: the TokenReview verdict could not be established.
			// Reject and do NOT fall through to the static path — never log the
			// token itself.
			m.logger.Warn("internal decisions ingest: TokenReview failed; rejecting (fail closed)",
				zap.Error(err),
			)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "invalid bearer token",
			})
			return
		}
		if ok {
			// Authenticated and audience-bound: admit.
			m.ingestEvent(c)
			return
		}
		// Clean negative verdict: fall through to the static fallback below.
	}

	// Static fallback (or the only path when no reviewer is configured).
	if !m.internalToken.Configured() {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "internal token not configured",
		})
		return
	}
	// Constant-time bearer-token verification (CRY-WU-13, IAM-WU-07): the
	// presented token is compared against the configured token(s) over
	// fixed-length digests so neither token contents nor length leak via timing.
	if !m.internalToken.Verify(raw) {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "invalid bearer token",
		})
		return
	}
	m.ingestEvent(c)
}

// ingestEvent decodes the PublicEvent body and publishes it to the bus + recent
// ring. It is the shared tail of IngestInternal, reached only after the caller
// has been authenticated by either the TokenReview or static path. Body handling
// is unchanged from the pre-IAM-WU-11 implementation.
func (m *Manager) ingestEvent(c *gin.Context) {
	var ev audit.PublicEvent
	// LENIENT DECODE: json.NewDecoder is used WITHOUT DisallowUnknownFields()
	// so the wire schema can be extended additively (new optional fields like
	// `suppressed_by`) without breaking existing publishers. If a future change
	// adds strict decoding here, every additive field on audit.PublicEvent
	// must be added to the publisher's struct in the SAME PR or audit records
	// will be silently dropped (plan §5.9.b / Critic MAJOR-N5).
	if err := json.NewDecoder(c.Request.Body).Decode(&ev); err != nil {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "invalid event body",
		})
		return
	}
	if ev.Decision == "" {
		c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{
			"error": "decision is required",
		})
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	m.bus.Publish(ev)
	m.recentRing.Add(ev)
	// WriteHeaderNow is required because gin buffers the status code and only
	// flushes it on the first body write. 204 has no body, so we must push it
	// explicitly — otherwise httptest.ResponseRecorder.Code stays 200.
	c.Status(http.StatusNoContent)
	c.Writer.WriteHeaderNow()
}

// StreamDecisions handles GET /api/v1/decisions/stream.
//
// SSE: emits `data: <json>\n\n` for each PublicEvent published to the bus.
// A heartbeat comment (`: heartbeat\n\n`) is sent every 15 s to keep
// proxies from timing out idle connections. The handler exits when the
// client disconnects (c.Request.Context().Done()) or the bus closes.
func (m *Manager) StreamDecisions(c *gin.Context) {
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")
	// Flush headers immediately so the HTTP client sees 200 + SSE headers
	// before the first event arrives. Without this, Do(req) blocks until the
	// first body write, creating a timing dependency in tests and real proxies.
	c.Writer.WriteHeaderNow()
	c.Writer.Flush()

	ch, cancel := m.bus.Subscribe()
	defer cancel()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	ctx := c.Request.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, open := <-ch:
			if !open {
				return
			}
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			_, _ = c.Writer.WriteString("data: " + string(data) + "\n\n")
			c.Writer.Flush()
		case <-ticker.C:
			_, _ = c.Writer.WriteString(": heartbeat\n\n")
			c.Writer.Flush()
		}
	}
}

// RecentDecisions handles GET /api/v1/decisions/recent?limit=N.
//
// Returns {"decisions":[...], "degraded": bool}. degraded is true when the
// ring is empty, signaling to the SPA that no events have been published yet.
// Default limit 20, max 100. Matches the dashboard's /api/decisions/recent shape.
func (m *Manager) RecentDecisions(c *gin.Context) {
	limit := 20
	if s := c.Query("limit"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			limit = n
		}
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 100 {
		limit = 100
	}
	items := m.recentRing.Recent(limit)
	c.JSON(http.StatusOK, gin.H{
		"decisions": items,
		"degraded":  len(items) == 0,
	})
}
