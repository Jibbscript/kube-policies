package main

import (
	"context"
	"crypto/tls"
	"errors"
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
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/Jibbscript/kube-policies/internal/admission"
	"github.com/Jibbscript/kube-policies/internal/audit"
	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/metrics"
	"github.com/Jibbscript/kube-policies/internal/policy"
	"github.com/Jibbscript/kube-policies/internal/policymanager"
	"github.com/Jibbscript/kube-policies/pkg/logger"
)

// Note on the --kubeconfig flag: controller-runtime's
// sigs.k8s.io/controller-runtime/pkg/client/config init() already registers
// the flag globally. Re-registering it here would panic with
// "flag redefined: kubeconfig" on startup. ctrl.GetConfig() reads it.

var (
	certPath    = flag.String("cert-path", "/etc/certs/tls.crt", "Path to TLS certificate")
	keyPath     = flag.String("key-path", "/etc/certs/tls.key", "Path to TLS private key")
	port        = flag.Int("port", 8443, "Webhook server port")
	metricsPort = flag.Int("metrics-port", 9090, "Metrics server port")
	configPath  = flag.String("config", "/etc/config/config.yaml", "Path to configuration file")

	// disableControllers turns off CRD watching. Off by default: the webhook
	// loads bundled defaults AND watches Policy CRDs so kubectl apply changes
	// real admission decisions. Operators who run an explicitly bundled-only
	// webhook (no RBAC for the policies.kube-policies.io group) flip this on.
	disableControllers = flag.Bool("disable-controllers", false, "Disable CRD reconcilers; enforce bundled-default policies only.")

	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	flag.Parse()

	// Initialize logger
	log := logger.NewLoggerFromEnv("admission-webhook")
	// Wire controller-runtime/klog to our zap pipeline BEFORE ctrl.GetConfig
	// (line ~137) so manager init and any client-go reflector chatter route
	// through the same JSON stream as the rest of this binary.
	logger.SetControllerRuntimeLogger(log)
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

	// Background-process context. Cancelled on SIGINT/SIGTERM below; the CRD
	// controllers stop when this is cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start CRD controllers so kubectl-applied Policy resources change real
	// admission decisions. Kubeconfig resolution failures are fatal by
	// default — the whole value proposition of the webhook in operator mode
	// is enforcing user-defined policies, so silently degrading to
	// bundled-only would be misleading. Operators that intentionally run in
	// API-only/bundled-only mode pass --disable-controllers.
	if !*disableControllers {
		// ctrl.GetConfig() resolves: --kubeconfig flag (auto-registered by
		// controller-runtime) > KUBECONFIG env > $HOME/.kube/config > in-cluster.
		restCfg, err := ctrl.GetConfig()
		if err != nil {
			log.Fatal("could not resolve a Kubernetes config for the CRD controllers",
				zap.Error(err),
				zap.String("hint", "set --kubeconfig=PATH, run inside a Pod with a service-account token, or pass --disable-controllers to fall back to bundled-default policies"),
			)
		}
		sink := newEngineSink(policyEngine, log.Named("engine-sink"))
		opts := policymanager.ControllerOptions{
			// Distinct lease ID — when both policy-manager and webhook run
			// controllers in the same namespace, they must not contend over
			// the same leader-election lease.
			LeaderElectionID: "kube-policies-admission-webhook",
			PolicySink:       sink,
			// ExceptionSink intentionally nil: the engine has no exception
			// enforcement path; wiring it would imply a behavior change that
			// is out of scope for the webhook extension.
		}
		go func() {
			log.Info("starting CRD controllers")
			if err := policymanager.StartControllers(ctx, restCfg, log, opts); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("CRD controller manager exited with error", zap.Error(err))
			}
		}()
	} else {
		log.Warn("CRD controllers disabled via --disable-controllers; admission decisions will use bundled-default policies only")
	}

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down servers...")

	cancel() // stop CRD controllers

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := webhookServer.Shutdown(shutdownCtx); err != nil {
		log.Error("Failed to shutdown webhook server", zap.Error(err))
	}

	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
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
