package policymanager

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/Jibbscript/kube-policies/internal/auth"
	"github.com/Jibbscript/kube-policies/internal/config"
)

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
func NewAPIRouter(m *Manager, authCfg config.AuthConfig, rbacCfg config.RBACConfig, verifier oidcVerifier) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})
	router.GET("/readyz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	// Management plane: human-facing CRUD + read RPCs. Guarded by OIDC authN +
	// RBAC when enabled.
	mgmt := router.Group("/api/v1")
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
	// endpoints. This group is intentionally NOT wrapped by the OIDC middleware
	// — it is a service-to-service plane, not a human one. /decisions/internal
	// keeps its own constant-time symmetric internal-token auth
	// (CRY-WU-13, IAM-WU-07); stream/recent are read-only ticker feeds.
	// Hardening of the inter-service authn for this plane (projected ServiceAccount
	// tokens) is tracked separately in IAM-WU-11.
	decisions := router.Group("/api/v1")
	{
		decisions.POST("/decisions/internal", m.IngestInternal)
		decisions.GET("/decisions/stream", m.StreamDecisions)
		decisions.GET("/decisions/recent", m.RecentDecisions)
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
