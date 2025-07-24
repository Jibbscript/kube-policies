package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/metrics"
	"github.com/Jibbscript/kube-policies/internal/policymanager"
	"github.com/Jibbscript/kube-policies/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

var (
	port        = flag.Int("port", 8080, "Policy manager server port")
	metricsPort = flag.Int("metrics-port", 9091, "Metrics server port")
	configPath  = flag.String("config", "/etc/config/config.yaml", "Path to configuration file")
)

func main() {
	flag.Parse()

	// Initialize logger
	log := logger.NewLogger("policy-manager", "info")
	defer log.Sync()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Initialize metrics
	metricsCollector := metrics.NewCollector()

	// Initialize policy manager
	policyManager, err := policymanager.NewManager(cfg, log)
	if err != nil {
		log.Fatal("Failed to initialize policy manager", zap.Error(err))
	}

	// Setup API server
	apiServer := setupAPIServer(policyManager, log)

	// Setup metrics server
	metricsServer := setupMetricsServer(metricsCollector)

	// Start servers
	go func() {
		log.Info("Starting metrics server", zap.Int("port", *metricsPort))
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start metrics server", zap.Error(err))
		}
	}()

	go func() {
		log.Info("Starting policy manager API server", zap.Int("port", *port))
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start API server", zap.Error(err))
		}
	}()

	// Start policy manager background processes
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go policyManager.Start(ctx)

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down servers...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	cancel() // Stop policy manager

	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		log.Error("Failed to shutdown API server", zap.Error(err))
	}

	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		log.Error("Failed to shutdown metrics server", zap.Error(err))
	}

	log.Info("Servers stopped")
}

func setupAPIServer(manager *policymanager.Manager, log *zap.Logger) *http.Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// Enable CORS for all origins
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})

	// Health check endpoints
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	router.GET("/readyz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	// Policy management API
	api := router.Group("/api/v1")
	{
		// Policy CRUD operations
		api.GET("/policies", manager.ListPolicies)
		api.GET("/policies/:id", manager.GetPolicy)
		api.POST("/policies", manager.CreatePolicy)
		api.PUT("/policies/:id", manager.UpdatePolicy)
		api.DELETE("/policies/:id", manager.DeletePolicy)

		// Policy testing
		api.POST("/policies/:id/test", manager.TestPolicy)
		api.POST("/policies/validate", manager.ValidatePolicy)

		// Policy deployment
		api.POST("/policies/:id/deploy", manager.DeployPolicy)
		api.GET("/policies/:id/status", manager.GetPolicyStatus)

		// Policy bundles
		api.GET("/bundles", manager.ListBundles)
		api.GET("/bundles/:id", manager.GetBundle)
		api.POST("/bundles", manager.CreateBundle)

		// Exception management
		api.GET("/exceptions", manager.ListExceptions)
		api.POST("/exceptions", manager.CreateException)
		api.PUT("/exceptions/:id", manager.UpdateException)
		api.DELETE("/exceptions/:id", manager.DeleteException)

		// Compliance reporting
		api.GET("/compliance/reports", manager.ListComplianceReports)
		api.POST("/compliance/reports", manager.GenerateComplianceReport)
		api.GET("/compliance/frameworks", manager.ListComplianceFrameworks)
	}

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return server
}

func setupMetricsServer(collector *metrics.Collector) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", *metricsPort),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	return server
}
