package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	"github.com/Jibbscript/kube-policies/internal/admission"
	"github.com/Jibbscript/kube-policies/internal/audit"
	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/metrics"
	"github.com/Jibbscript/kube-policies/internal/policy"
	"github.com/Jibbscript/kube-policies/pkg/logger"
)

var (
	certPath    = flag.String("cert-path", "/etc/certs/tls.crt", "Path to TLS certificate")
	keyPath     = flag.String("key-path", "/etc/certs/tls.key", "Path to TLS private key")
	port        = flag.Int("port", 8443, "Webhook server port")
	metricsPort = flag.Int("metrics-port", 9090, "Metrics server port")
	configPath  = flag.String("config", "/etc/config/config.yaml", "Path to configuration file")

	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	flag.Parse()

	// Initialize logger
	log := logger.NewLogger("admission-webhook", "info")
	defer func() { _ = log.Sync() }()

	log.Info("admission-webhook starting",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("date", date),
	)

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Initialize metrics
	metricsCollector := metrics.NewCollector()

	// Initialize audit logger
	auditLogger, err := audit.NewLogger(&cfg.Audit,
		audit.WithLogger(log),
		audit.WithMetrics(metricsCollector),
	)
	if err != nil {
		log.Fatal("Failed to initialize audit logger", zap.Error(err))
	}

	// Initialize policy engine
	policyEngine, err := policy.NewEngine(&cfg.Policy, log)
	if err != nil {
		log.Fatal("Failed to initialize policy engine", zap.Error(err))
	}

	// Initialize decision publisher (fire-and-forget forwarding to policy-manager).
	// If POLICY_MANAGER_INTERNAL_TOKEN is empty the publisher is a no-op.
	pmURL := os.Getenv("POLICY_MANAGER_INTERNAL_URL")
	if pmURL == "" {
		pmURL = "http://policy-manager:8080/api/v1/decisions/internal"
	}
	pmToken := os.Getenv("POLICY_MANAGER_INTERNAL_TOKEN")
	publisher := admission.NewDecisionPublisher(pmURL, pmToken, log, metricsCollector)
	defer publisher.Stop()

	// Initialize admission controller
	admissionController := admission.NewController(policyEngine, auditLogger, metricsCollector, log, publisher)

	// Setup webhook server
	webhookServer := setupWebhookServer(admissionController, log)

	// Setup metrics server
	metricsServer := setupMetricsServer()

	// Start servers
	go func() {
		log.Info("Starting metrics server", zap.Int("port", *metricsPort))
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start metrics server", zap.Error(err))
		}
	}()

	go func() {
		log.Info("Starting webhook server", zap.Int("port", *port))
		if err := webhookServer.ListenAndServeTLS(*certPath, *keyPath); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start webhook server", zap.Error(err))
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down servers...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := webhookServer.Shutdown(ctx); err != nil {
		log.Error("Failed to shutdown webhook server", zap.Error(err))
	}

	if err := metricsServer.Shutdown(ctx); err != nil {
		log.Error("Failed to shutdown metrics server", zap.Error(err))
	}

	log.Info("Servers stopped")
}

func setupWebhookServer(controller *admission.Controller, log *zap.Logger) *http.Server {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	// Health check endpoints
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	router.GET("/readyz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	// Admission webhook endpoints
	router.POST("/validate", controller.ValidateHandler)
	router.POST("/mutate", controller.MutateHandler)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", *port),
		Handler: router,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_AES_128_GCM_SHA256,
			},
		},
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return server
}

func setupMetricsServer() *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
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
