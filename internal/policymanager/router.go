package policymanager

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// NewAPIRouter returns the gin.Engine that backs the policy-manager API on
// :8080. It is exported so integration tests can mount the real route table
// against an in-process Manager via httptest.Server, without duplicating
// the route definitions in test setup. cmd/policy-manager/main.go calls this
// to construct the production server.
//
// CORS is intentionally not configured here: the policy-manager API is
// deployed behind an ingress/mesh that owns CORS, auth, and TLS termination.
func NewAPIRouter(m *Manager) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})
	router.GET("/readyz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	api := router.Group("/api/v1")
	{
		// Policy CRUD
		api.GET("/policies", m.ListPolicies)
		api.GET("/policies/:id", m.GetPolicy)
		api.POST("/policies", m.CreatePolicy)
		api.PUT("/policies/:id", m.UpdatePolicy)
		api.DELETE("/policies/:id", m.DeletePolicy)

		// Policy evaluation (RPC, no persistence)
		api.POST("/policies/:id/test", m.TestPolicy)
		api.POST("/policies/validate", m.ValidatePolicy)
		api.POST("/policies/evaluate", m.EvaluatePolicy)

		// Policy lifecycle (stubs)
		api.POST("/policies/:id/deploy", m.DeployPolicy)
		api.GET("/policies/:id/status", m.GetPolicyStatus)

		// Bundles
		api.GET("/bundles", m.ListBundles)
		api.GET("/bundles/:id", m.GetBundle)
		api.POST("/bundles", m.CreateBundle)

		// Exceptions
		api.GET("/exceptions", m.ListExceptions)
		api.POST("/exceptions", m.CreateException)
		api.PUT("/exceptions/:id", m.UpdateException)
		api.DELETE("/exceptions/:id", m.DeleteException)

		// Compliance (stubs)
		api.GET("/compliance/reports", m.ListComplianceReports)
		api.POST("/compliance/reports", m.GenerateComplianceReport)
		api.GET("/compliance/frameworks", m.ListComplianceFrameworks)

		// Decisions live-ticker (M2)
		api.POST("/decisions/internal", m.IngestInternal)
		api.GET("/decisions/stream", m.StreamDecisions)
		api.GET("/decisions/recent", m.RecentDecisions)
	}

	return router
}

// NewMetricsRouter returns the http.Handler exposed on :9091. Promhttp is
// wired against the global Prometheus registry that metrics.NewCollector()
// populates, so the metrics text format reflects whatever was registered in
// the current process. /healthz is included so a liveness probe can target
// the metrics port directly.
func NewMetricsRouter() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	return mux
}
