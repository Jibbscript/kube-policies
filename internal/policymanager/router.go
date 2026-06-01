package policymanager

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Jibbscript/kube-policies/internal/auth"
	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/middleware"
)

// correlationContextKey is the gin.Context key under which the per-request
// correlation id is stashed by CorrelationMiddleware (AUD-WU-20, AU-12(1)).
const correlationContextKey = "correlation_id"

// correlationHeader / correlationFallbackHeader are the inbound headers a caller
// may use to propagate a correlation id across the admission -> policy-manager ->
// dashboard request chain. X-Correlation-Id wins; X-Request-Id is the fallback.
const (
	correlationHeader         = "X-Correlation-Id"
	correlationFallbackHeader = "X-Request-Id"
)

// CorrelationMiddleware reads an inbound X-Correlation-Id (or X-Request-Id)
// header, synthesizing a uuid when neither is present, stashes it on the gin
// context under correlationContextKey, and echoes it back as the
// X-Correlation-Id response header (AUD-WU-20, AU-12(1)). Every management-plane
// mutation handler folds this id into its audit changes map via
// correlationIDFromContext so a single logical request is traceable across
// components.
//
// Trusting a caller-supplied header here is a NEW, explicit opt-in and does not
// reopen the source_ip spoofing concern that motivates router.SetTrustedProxies(nil):
// the correlation id is a non-authoritative trace key, never an authorization or
// attribution input.
func CorrelationMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(correlationHeader)
		if id == "" {
			id = c.GetHeader(correlationFallbackHeader)
		}
		if id == "" {
			id = uuid.NewString()
		}
		c.Set(correlationContextKey, id)
		c.Header(correlationHeader, id)
		c.Next()
	}
}

// correlationIDFromContext returns the correlation id stashed by
// CorrelationMiddleware, or "" when none is present (e.g. a route mounted
// without the middleware). Callers fold the returned id into the audit changes
// map under "correlation_id" so audit.Logger hoists it onto Event.CorrelationID.
func correlationIDFromContext(c *gin.Context) string {
	if v, ok := c.Get(correlationContextKey); ok {
		if id, ok := v.(string); ok {
			return id
		}
	}
	return ""
}

// NewAPIRouter returns the gin.Engine that backs the policy-manager API on
// :8080. It is exported so integration tests can mount the real route table
// against an in-process Manager via httptest.Server, without duplicating
// the route definitions in test setup. cmd/policy-manager/main.go calls this
// to construct the production server.
//
// AuthN/RBAC are config-gated by security.authentication.enabled. When that
// flag is true and verifier is non-nil, the management plane
// (policies/bundles/exceptions/compliance) is protected by OIDC bearer authN
// (IAM-WU-01) plus group-to-role RBAC (IAM-WU-02). When the flag is false the
// /api/v1 management plane is served UNAUTHENTICATED — a dev-only path that
// cmd/policy-manager/main.go logs as a startup warning and that remains a
// tracked gap. This function does not itself force authN on; production
// deployments MUST set security.authentication.enabled=true together with
// issuer/jwks_url/audience. The Helm production values do this, and the chart
// fails to render otherwise — but that guarantee lives in the chart, not here.
//
// CORS is intentionally not configured here: the policy-manager API is
// deployed behind an ingress/mesh that owns CORS, auth, and TLS termination.
func NewAPIRouter(m *Manager, authCfg config.AuthConfig, rbacCfg config.RBACConfig, verifier oidcVerifier, rlCfg config.RateLimitConfig, rlMetrics middleware.Metrics) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	// Trust no proxy headers: c.ClientIP() returns the non-spoofable direct
	// peer from RemoteAddr (IAM-WU-14 audit attribution). The policy-manager
	// sits behind its own TLS listener; any X-Forwarded-For header from an
	// untrusted upstream must not influence the audit record. This also
	// silences gin's "trusted proxies" startup warning.
	_ = router.SetTrustedProxies(nil)
	router.Use(gin.Recovery())

	// Health endpoints are registered BEFORE the rate-limit middleware so the
	// kubelet probes are never throttled (NET-WU-15).
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})
	router.GET("/readyz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	// Rate-limiting / DoS-protection (NET-WU-15, RES-WU-17): token-bucket rate
	// limit + in-flight concurrency cap (429) + request-body cap (413), applied
	// to the API groups below. A dedicated StreamGate (separate from the general
	// concurrency cap) bounds the long-lived /decisions/stream connections so SSE
	// subscribers cannot exhaust the request limiter (NET-WU-15).
	limiter := middleware.New(middleware.Config{
		RequestsPerSecond: rlCfg.RequestsPerSecond,
		Burst:             rlCfg.Burst,
		MaxConcurrent:     rlCfg.MaxConcurrent,
		MaxBodyBytes:      rlCfg.MaxBodyBytes,
		Enabled:           rlCfg.Enabled,
	}, rlMetrics)
	requestLimit := limiter.RequestMiddleware()
	var streamGate gin.HandlerFunc
	if rlCfg.Enabled {
		streamGate = middleware.NewStreamGate(rlCfg.MaxStreamConnections, "/api/v1/decisions/stream", rlMetrics).Middleware()
	} else {
		streamGate = func(c *gin.Context) { c.Next() }
	}

	// Management plane: human-facing CRUD + read RPCs. Guarded by OIDC authN +
	// RBAC when enabled, and the rate-limit middleware always.
	mgmt := router.Group("/api/v1")
	mgmt.Use(requestLimit)
	// Correlation id propagation (AUD-WU-20, AU-12(1)): stash an inbound
	// X-Correlation-Id / X-Request-Id (or a synthesized uuid) so every persisting
	// mutation handler can fold it into its audit changes map. Installed before
	// authN so even rejected requests carry a trace id in their response header.
	mgmt.Use(CorrelationMiddleware())
	if authCfg.Enabled && verifier != nil {
		mgmt.Use(OIDCAuthMiddleware(verifier, authCfg), RBACMiddleware(rbacCfg))
	}
	{
		// Policy CRUD
		mgmt.GET("/policies", m.ListPolicies)
		mgmt.GET("/policies/:id", m.GetPolicy)
		mgmt.POST("/policies", m.CreatePolicy)
		mgmt.PUT("/policies/:id", m.UpdatePolicy)
		mgmt.DELETE("/policies/:id", m.DeletePolicy)

		// Policy evaluation (RPC, no persistence)
		mgmt.POST("/policies/:id/test", m.TestPolicy)
		mgmt.POST("/policies/validate", m.ValidatePolicy)
		mgmt.POST("/policies/evaluate", m.EvaluatePolicy)

		// Policy lifecycle (stubs)
		mgmt.POST("/policies/:id/deploy", m.DeployPolicy)
		mgmt.GET("/policies/:id/status", m.GetPolicyStatus)

		// Bundles
		mgmt.GET("/bundles", m.ListBundles)
		mgmt.GET("/bundles/:id", m.GetBundle)
		mgmt.POST("/bundles", m.CreateBundle)

		// Exceptions
		mgmt.GET("/exceptions", m.ListExceptions)
		mgmt.POST("/exceptions", m.CreateException)
		mgmt.PUT("/exceptions/:id", m.UpdateException)
		mgmt.DELETE("/exceptions/:id", m.DeleteException)

		// Compliance (stubs)
		mgmt.GET("/compliance/reports", m.ListComplianceReports)
		mgmt.POST("/compliance/reports", m.GenerateComplianceReport)
		mgmt.GET("/compliance/frameworks", m.ListComplianceFrameworks)
	}

	// Decisions machine-plane (M2): the live-ticker ingest/stream/recent
	// endpoints. This group is intentionally NOT wrapped by the OIDC human-auth
	// middleware — it is a service-to-service plane, not a human one. All three
	// routes nonetheless require a valid SERVICE token (IAM-WU-11, Inc7 Stream A);
	// none is unauthenticated:
	//   - /decisions/internal authenticates the WEBHOOK SA (IngestInternal pins
	//     m.internalReviewer to the webhook SA's audience-bound projected token
	//     via the Kubernetes TokenReview API).
	//   - /decisions/stream + /decisions/recent authenticate the DASHBOARD SA
	//     (DecisionsReadAuth middleware pins m.decisionsReadReviewer to the
	//     dashboard SA over the SAME audience).
	// All paths fall through to the constant-time symmetric internal-token
	// verifier (CRY-WU-13, IAM-WU-07) as an opt-in static fallback for
	// non-cluster/demo (static-mode) deployments. Only OIDC human-auth is exempt
	// here, NOT authentication itself.
	decisions := router.Group("/api/v1")
	decisions.Use(requestLimit)
	{
		decisions.POST("/decisions/internal", m.IngestInternal)
		// The read feeds are service-authed via DecisionsReadAuth (dashboard-SA
		// TokenReview + static fallback), applied per-route so /internal keeps
		// its own webhook-SA pin in IngestInternal. The stream gate caps
		// concurrent SSE connections (NET-WU-15) and is applied before the auth
		// middleware so an over-cap connection is rejected with 429 without a
		// TokenReview round-trip.
		decisions.GET("/decisions/stream", streamGate, m.DecisionsReadAuth(), m.StreamDecisions)
		decisions.GET("/decisions/recent", m.DecisionsReadAuth(), m.RecentDecisions)
	}

	return router
}

// NewMetricsRouter returns the http.Handler exposed on :9091. Promhttp is
// wired against the global Prometheus registry that metrics.NewCollector()
// populates, so the metrics text format reflects whatever was registered in
// the current process. /healthz is included so a liveness probe can target
// the metrics port directly.
// NewMetricsRouter builds the :9091 metrics handler. When verifier is non-nil,
// /metrics is wrapped with bearer-token auth (CRY-WU-08); /healthz and /readyz
// are always left open so kubelet probes (which send no Authorization header)
// keep working. A nil verifier yields unauthenticated /metrics (the plain-HTTP
// default).
func NewMetricsRouter(verifier *auth.TokenVerifier) http.Handler {
	mux := http.NewServeMux()
	var metricsHandler http.Handler = promhttp.Handler()
	if verifier != nil {
		metricsHandler = auth.RequireBearer(verifier, metricsHandler)
	}
	mux.Handle("/metrics", metricsHandler)
	// /healthz and /readyz are served on the metrics port so the kubelet
	// liveness/readiness probes can target it instead of the TLS-only :8080 API
	// listener (CRY-WU-05). They stay unauthenticated.
	healthHandler := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	}
	mux.HandleFunc("/healthz", healthHandler)
	mux.HandleFunc("/readyz", healthHandler)
	return mux
}
