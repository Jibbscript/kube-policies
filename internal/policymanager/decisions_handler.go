package policymanager

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Jibbscript/kube-policies/internal/audit"
	"github.com/gin-gonic/gin"
)

// IngestInternal handles POST /api/v1/decisions/internal.
//
// Auth: Authorization: Bearer <internalToken>. If the stored token is empty
// (unconfigured) the endpoint returns 401 on every request — an empty token
// must not act as a wildcard.
func (m *Manager) IngestInternal(c *gin.Context) {
	if m.internalToken == "" {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "internal token not configured",
		})
		return
	}
	auth := c.GetHeader("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) || strings.TrimPrefix(auth, prefix) != m.internalToken {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error": "invalid bearer token",
		})
		return
	}
	var ev audit.PublicEvent
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
// ring is empty, signalling to the SPA that no events have been published yet.
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
