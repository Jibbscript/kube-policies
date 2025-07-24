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

	"github.com/Jibbscript/kube-policies/internal/admission"
	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/metrics"
	"github.com/Jibbscript/kube-policies/internal/policy"
	"github.com/Jibbscript/kube-policies/pkg/audit"
	"github.com/Jibbscript/kube-policies/pkg/logger"
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

var (
	certPath    = flag.String("cert-path", "/etc/certs/tls.crt", "Path to TLS certificate")
	keyPath     = flag.String("key-path", "/etc/certs/tls.key", "Path to TLS private key")
	port        = flag.Int("port", 8443, "Webhook server port")
	metricsPort = flag.Int("metrics-port", 9090, "Metrics server port")
	configPath  = flag.String("config", "/etc/config/config.yaml", "Path to configuration file")
)

func main() {
	flag.Parse()

	// Initialize logger
	log := logger.NewLogger("admission-webhook", "info")
	defer log.Sync()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Initialize metrics
	metricsCollector := metrics.NewCollector()

	// Initialize audit logger
	auditLogger, err := audit.NewLogger(&cfg.Audit)
	if err != nil {
		log.Fatal("Failed to initialize audit logger", zap.Error(err))
	}

	// Initialize policy engine
	policyEngine, err := policy.NewEngine(&cfg.Policy, log)
	if err != nil {
		log.Fatal("Failed to initialize policy engine", zap.Error(err))
	}

	// Initialize admission controller
	admissionController := admission.NewController(policyEngine, auditLogger, metricsCollector, log)

	// Setup webhook server
	webhookServer := setupWebhookServer(admissionController, log)

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
