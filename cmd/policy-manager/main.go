package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go.uber.org/zap"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/cryptofips"
	"github.com/Jibbscript/kube-policies/internal/metrics"
	"github.com/Jibbscript/kube-policies/internal/policymanager"
	"github.com/Jibbscript/kube-policies/internal/tlsreload"
	"github.com/Jibbscript/kube-policies/pkg/logger"
)

// Note on the --kubeconfig flag: controller-runtime's
// sigs.k8s.io/controller-runtime/pkg/client/config init() already registers
// the flag globally. Re-registering it here would panic with
// "flag redefined: kubeconfig" on startup. ctrl.GetConfig() reads it.

var (
	port        = flag.Int("port", 8080, "Policy manager server port")
	metricsPort = flag.Int("metrics-port", 9091, "Metrics server port")
	configPath  = flag.String("config", "/etc/config/config.yaml", "Path to configuration file")
	certPath    = flag.String("cert-path", "/etc/certs/tls.crt", "Path to TLS certificate for the API server")
	keyPath     = flag.String("key-path", "/etc/certs/tls.key", "Path to TLS private key for the API server")

	// disableControllers disables the CRD reconcilers. Off by default — the
	// whole point of the policy-manager is to reconcile Policy and
	// PolicyException CRDs into its in-memory registry. Operators running
	// without RBAC access to the policies.kube-policies.io group can flip
	// this to keep the HTTP API functional with bundled defaults only.
	disableControllers = flag.Bool("disable-controllers", false, "Disable CRD reconcilers; serve only bundled defaults via the HTTP API.")

	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	flag.Parse()

	// Initialize logger
	log := logger.NewLoggerFromEnv("policy-manager")
	// Wire controller-runtime/klog to our zap pipeline BEFORE ctrl.GetConfig
	// (line ~127) so manager init and any client-go reflector chatter route
	// through the same JSON stream as the rest of this binary.
	logger.SetControllerRuntimeLogger(log)
	defer func() { _ = log.Sync() }()

	log.Info("policy-manager starting",
		zap.String("version", version),
		zap.String("commit", commit),
		zap.String("date", date),
	)

	// FIPS 140-3 startup self-test (CRY-WU-02): abort before opening any
	// listener when REQUIRE_FIPS=true but the validated module is not active.
	cryptofips.MustEnforce(log)

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatal("Failed to load configuration", zap.Error(err))
	}

	// Initialize metrics (registers collectors against the global Prometheus registry).
	_ = metrics.NewCollector()

	// Initialize policy manager
	policyManager, err := policymanager.NewManager(cfg, log)
	if err != nil {
		log.Fatal("Failed to initialize policy manager", zap.Error(err))
	}
	// Accept both the current and (during a rotation window) the previous
	// internal token so secret rotation causes no downtime (CRY-WU-14).
	policyManager.SetInternalTokens(
		os.Getenv("POLICY_MANAGER_INTERNAL_TOKEN"),
		os.Getenv("POLICY_MANAGER_INTERNAL_TOKEN_PREVIOUS"),
	)

	// Background-process context. Canceled on SIGINT/SIGTERM below; the CRD
	// controllers, the policy manager, and the TLS cert reloader stop when this
	// is canceled. Created BEFORE the servers start so the reloader shares it.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup API server and metrics server. Router definitions live in
	// internal/policymanager so integration tests can mount the same routes
	// against an in-process Manager without duplicating the route table.
	//
	// The API server (:8080) serves TLS 1.3 (CRY-WU-05): the internal bearer
	// token previously crossed this listener in plaintext. TLS parameters are
	// config-driven (CRY-WU-03) and the certificate is served via a hot-reload
	// callback (CRY-WU-10). The metrics server (:9091) stays plain HTTP — it
	// carries no secret and is the target of the liveness/readiness probes and
	// the Prometheus scrape.
	tlsConf, err := config.BuildServerTLSConfig(cfg.Security.TLS, nil)
	if err != nil {
		log.Fatal("Failed to build API TLS config", zap.Error(err))
	}
	certReloader, err := tlsreload.New(*certPath, *keyPath, log.Named("tls-reload"))
	if err != nil {
		log.Fatal("Failed to load API TLS certificate", zap.Error(err))
	}
	tlsConf.GetCertificate = certReloader.GetCertificate
	go func() {
		if err := certReloader.Start(ctx); err != nil {
			log.Error("TLS certificate reloader stopped with error", zap.Error(err))
		}
	}()

	apiServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      policymanager.NewAPIRouter(policyManager),
		TLSConfig:    tlsConf,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	metricsServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", *metricsPort),
		Handler:      policymanager.NewMetricsRouter(),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	// Start servers
	go func() {
		log.Info("Starting metrics server", zap.Int("port", *metricsPort))
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start metrics server", zap.Error(err))
		}
	}()

	go func() {
		log.Info("Starting policy manager API server (TLS)", zap.Int("port", *port))
		// Empty cert/key paths: the certificate is served via
		// TLSConfig.GetCertificate (the reloader), not a one-shot file read.
		if err := apiServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start API server", zap.Error(err))
		}
	}()

	go policyManager.Start(ctx)

	// Start the CRD controllers unless explicitly disabled. The controllers
	// run inside the same process as the HTTP API, sharing the in-memory
	// registry: a CRD applied through kubectl becomes visible on /api/v1/policies
	// after one reconcile pass (typically <1s on a healthy apiserver).
	//
	// CRD reconciliation is the policy-manager's defining responsibility, so
	// kubeconfig resolution failures are fatal by default. Operators who
	// genuinely intend to run the API in API-only mode (developer workflows,
	// SPA work against bundled defaults) must pass --disable-controllers
	// explicitly; this prevents misconfigured deployments from silently
	// serving stale data.
	if !*disableControllers {
		// ctrl.GetConfig() resolves: --kubeconfig flag (auto-registered by
		// controller-runtime) > KUBECONFIG env > $HOME/.kube/config > in-cluster.
		restCfg, err := ctrl.GetConfig()
		if err != nil {
			log.Fatal("could not resolve a Kubernetes config for the CRD controllers",
				zap.Error(err),
				zap.String("hint", "set --kubeconfig=PATH, run inside a Pod with a service-account token, or pass --disable-controllers if you intentionally want API-only mode"),
			)
		}
		ns, err := policymanager.ResolvePodNamespace("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			log.Fatal("could not resolve pod namespace for leader election",
				zap.Error(err),
				zap.String("hint", "set POD_NAMESPACE env or run inside a Pod with a service-account token, or pass --disable-controllers if you intentionally want API-only mode"),
			)
		}
		go func() {
			log.Info("starting CRD controllers")
			// The policy-manager consumes both kinds: Policies feed the
			// HTTP/list registry, Exceptions feed /api/v1/exceptions.
			opts := policymanager.ControllerOptions{
				LeaderElectionID:        "kube-policies-policy-manager",
				LeaderElectionNamespace: ns,
				PolicySink:              policyManager,
				ExceptionSink:           policyManager,
				// DisableLeaderElection: zero value (false) → election ENABLED.
			}
			if err := policymanager.StartControllers(ctx, restCfg, log, opts); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("CRD controller manager exited with error", zap.Error(err))
			}
		}()
	} else {
		log.Warn("CRD controllers disabled via --disable-controllers; the HTTP API will serve only bundled-default policies")
	}

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("Shutting down servers...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	cancel() // Stop policy manager and CRD controllers

	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		log.Error("Failed to shutdown API server", zap.Error(err))
	}

	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		log.Error("Failed to shutdown metrics server", zap.Error(err))
	}

	log.Info("Servers stopped")
}
