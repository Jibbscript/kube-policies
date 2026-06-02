package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/Jibbscript/kube-policies/internal/admission"
	"github.com/Jibbscript/kube-policies/internal/audit"
	"github.com/Jibbscript/kube-policies/internal/auth"
	"github.com/Jibbscript/kube-policies/internal/config"
	"github.com/Jibbscript/kube-policies/internal/cryptofips"
	"github.com/Jibbscript/kube-policies/internal/metrics"
	"github.com/Jibbscript/kube-policies/internal/middleware"
	"github.com/Jibbscript/kube-policies/internal/policy"
	"github.com/Jibbscript/kube-policies/internal/policymanager"
	"github.com/Jibbscript/kube-policies/internal/tlsreload"
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

	// clientCAPath, when set, makes client_auth=require enforce mutual TLS
	// (RequireAndVerifyClientCert) against this PEM bundle (CRY-WU-04). When
	// empty, client-certificate verification is disabled even if
	// client_auth=require. Flag value overrides the config-file value.
	clientCAPath = flag.String("client-ca-path", "", "Path to PEM client-CA bundle for webhook mTLS; empty disables client-cert verification")

	// requireClientCert is the secure-by-default mTLS enforcement switch
	// (IAM-WU-06). When true (the default), the webhook FAILS CLOSED at startup
	// unless a client-CA bundle is supplied (--client-ca-path /
	// security.tls.client_ca_path), and the resulting listener requires + verifies
	// the apiserver client certificate (RequireAndVerifyClientCert) regardless of
	// the config's client_auth string. Set false ONLY as a documented break-glass
	// for clusters that cannot supply an apiserver client cert; the binary then
	// loudly warns that mTLS is OFF. NOTE: the shipped DEV artifacts (Helm dev
	// values, kustomize base) explicitly opt into break-glass — the webhook is
	// enforce-by-default in the binary but NOT in those dev manifests.
	requireClientCert = flag.Bool("require-client-cert", true, "Require and verify the apiserver client certificate (mTLS). Default true (fail closed). Set false ONLY as a documented break-glass for clusters that cannot supply an apiserver client cert.")

	// policyManagerCAPath is the PEM bundle trusted when the webhook connects to
	// the policy-manager API over TLS (CRY-WU-06). Empty (default) falls back to
	// the system root pool; the chart sets this and mounts the policy-manager
	// serving CA so the in-cluster self-signed / cert-manager cert verifies.
	policyManagerCAPath = flag.String("policy-manager-ca-path", "", "Path to PEM CA bundle trusted for the policy-manager TLS connection; empty uses system roots")

	// policyManagerClientCertPath / policyManagerClientKeyPath, when BOTH set, make
	// the decision publisher PRESENT a client certificate to the policy-manager for
	// mutual TLS (IAM-WU-03) — authenticating the webhook as a service caller when
	// the policy-manager enforces --require-client-cert. Empty (default) keeps the
	// server-auth-only connection (CRY-WU-06). The cert is hot-reloaded so a
	// cert-manager rotation needs no restart.
	policyManagerClientCertPath = flag.String("policy-manager-client-cert-path", "", "Path to the PEM client certificate presented to the policy-manager for mTLS (IAM-WU-03); empty disables client-cert presentation")
	policyManagerClientKeyPath  = flag.String("policy-manager-client-key-path", "", "Path to the private key for --policy-manager-client-cert-path")

	// policyManagerTokenPath, when set, makes the decision publisher present a
	// rotating, audience-bound projected ServiceAccount token read from this file
	// instead of the static POLICY_MANAGER_INTERNAL_TOKEN env (IAM-WU-11). The
	// chart mounts a projected serviceAccountToken volume (audience=policy-manager,
	// short TTL) here; the kubelet atomically swaps it as it rotates. Empty
	// (default) keeps the legacy static-token behavior (backward compatible).
	policyManagerTokenPath = flag.String("policy-manager-token-path", "", "Path to a projected ServiceAccount token file presented to the policy-manager on the decisions channel (IAM-WU-11); takes precedence over POLICY_MANAGER_INTERNAL_TOKEN. Empty uses the static env token.")

	// metricsTLS, when set, serves the :9090 metrics endpoint over TLS 1.3 and
	// requires a bearer token on /metrics (CRY-WU-08). /healthz stays open for
	// probes. Default off so plain-HTTP scraping/probing keeps working.
	metricsTLS = flag.Bool("metrics-tls", false, "Serve /metrics over TLS 1.3 with bearer-token auth (CRY-WU-08)")

	// disableControllers turns off CRD watching. Off by default: the webhook
	// loads bundled defaults AND watches Policy CRDs so kubectl apply changes
	// real admission decisions. Operators who run an explicitly bundled-only
	// webhook (no RBAC for the policies.kube-policies.io group) flip this on.
	disableControllers = flag.Bool("disable-controllers", false, "Disable CRD reconcilers; enforce bundled-default policies only.")

	// disableDefaults skips loading the bundled default policies entirely.
	// Useful for testing with a clean engine or deploying with only user-defined policies.
	disableDefaults = flag.Bool("disable-default-policies", false, "Skip loading bundled default policies")

	// Rate-limiting / DoS-protection flag overrides (NET-WU-14, RES-WU-17).
	// Each defaults to a sentinel that means "use the config-file value"
	// (security.ratelimit.*): -1 for the numeric limits, false for the
	// disable switch. A non-negative override wins over config. The webhook is
	// on the cluster's critical write path, so the config defaults are tuned to
	// reject floods without throttling legitimate apiserver admission traffic;
	// see internal/config/config.go RateLimitConfig.
	rateLimitDisabled      = flag.Bool("ratelimit-disabled", false, "Disable the HTTP rate-limit / DoS-protection middleware (overrides security.ratelimit.enabled)")
	rateLimitRPS           = flag.Float64("ratelimit-requests-per-second", -1, "Sustained request rate (req/s) for the rate limiter; -1 uses security.ratelimit.requests_per_second")
	rateLimitBurst         = flag.Int("ratelimit-burst", -1, "Token-bucket burst depth; -1 uses security.ratelimit.burst")
	rateLimitMaxConcurrent = flag.Int("ratelimit-max-concurrent", -1, "Max in-flight requests; -1 uses security.ratelimit.max_concurrent")
	rateLimitMaxBodyBytes  = flag.Int64("ratelimit-max-body-bytes", -1, "Max request body size in bytes (413 when exceeded); -1 uses security.ratelimit.max_body_bytes")

	// maxConcurrentReconciles bounds the per-reconciler worker pool (RES-WU-17).
	// <= 0 defers to the policymanager package default (2).
	maxConcurrentReconciles = flag.Int("max-concurrent-reconciles", 2, "Max concurrent reconciles per CRD reconciler (RES-WU-17 DoS protection)")

	// shutdownDrainDelay is the graceful-drain window (RES-WU-07, CP-10/SC-5). On
	// SIGTERM the webhook first marks itself NotReady (so the apiserver stops
	// routing admission to it) and then KEEPS SERVING for this delay before
	// closing the listener, so the endpoints/kube-proxy removal propagates and no
	// in-flight admission call is dropped (fail-closed denied) mid-rollout. This is
	// the image- and version-independent equivalent of a preStop sleep hook: the
	// runtime images are distroless (no shell for an exec sleep) and the native
	// lifecycle `sleep` action only exists on k8s >= 1.29. 0 disables the drain.
	shutdownDrainDelay = flag.Duration("shutdown-drain-delay", 5*time.Second, "Graceful-drain delay after SIGTERM before the webhook stops serving, to let Service endpoints propagate the NotReady state (RES-WU-07). 0 disables.")

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

	// FIPS 140-3 startup self-test (CRY-WU-02): abort before opening any
	// listener when REQUIRE_FIPS=true but the validated module is not active.
	cryptofips.MustEnforce(log)

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

	// Apply flag overrides to policy config before engine construction
	log.Info("disable-default-policies flag", zap.Bool("disable_default_policies", *disableDefaults))
	cfg.Policy.DisableDefaults = *disableDefaults

	// Flag overrides config for the client-CA bundle path (CRY-WU-04): an
	// explicit --client-ca-path wins over any config-file value.
	if *clientCAPath != "" {
		cfg.Security.TLS.ClientCAPath = *clientCAPath
	}

	// Initialize policy engine.
	//
	// Conditional construction (plan §5.5, engine-exception-consumption):
	// under --disable-controllers the engine is built via NewEngine with no
	// registry — the nil-branch in Evaluate is the live production code path,
	// preserving Principle 5 (flag flip changes no observable allow/deny).
	// With controllers enabled, a single *exceptionSink is constructed and
	// passed as BOTH:
	//   - the engine's ExceptionRegistry (read side) via NewEngineWithExceptions
	//   - the reconciler's ExceptionSink (write side) via ControllerOptions below
	var (
		policyEngine *policy.Engine
		excSink      *exceptionSink // non-nil only when controllers are enabled
	)
	if *disableControllers {
		policyEngine, err = policy.NewEngine(&cfg.Policy, log)
		if err != nil {
			log.Fatal("Failed to initialize policy engine", zap.Error(err))
		}
		log.Info("exception sink not wired (--disable-controllers set; bundled-only enforcement)")
	} else {
		excSink = newExceptionSink(log.Named("exception-sink"))
		policyEngine, err = policy.NewEngineWithExceptions(&cfg.Policy, log, excSink)
		if err != nil {
			log.Fatal("Failed to initialize policy engine", zap.Error(err))
		}
		log.Info("exception sink wired into engine (CRD reconciler enabled)")
	}

	// Initialize decision publisher (fire-and-forget forwarding to policy-manager).
	// If POLICY_MANAGER_INTERNAL_TOKEN is empty the publisher is a no-op.
	//
	// The policy-manager API now serves TLS 1.3 (CRY-WU-05), so the publisher
	// connects over verified HTTPS (CRY-WU-06): the bearer token never crosses
	// a plaintext connection. The policy-manager serving CA is loaded from
	// --policy-manager-ca-path into RootCAs; an empty path falls back to the
	// system root pool. InsecureSkipVerify is never used.
	pmURL := os.Getenv("POLICY_MANAGER_INTERNAL_URL")
	if pmURL == "" {
		pmURL = "https://policy-manager:8080/api/v1/decisions/internal"
	}
	pmToken := os.Getenv("POLICY_MANAGER_INTERNAL_TOKEN")
	// Non-fatal: the publisher is fire-and-forget telemetry, and the
	// policy-manager CA (cert-manager path) may lag the webhook's start. If the
	// CA cannot be loaded, fall back to system roots and warn — verification
	// still applies (no InsecureSkipVerify), so an unverifiable connection just
	// drops decisions; the token never crosses a plaintext connection. The
	// webhook's own admission path is unaffected.
	// Optionally present a client certificate to the policy-manager for mutual TLS
	// (IAM-WU-03). The reloader's initial load is synchronous, so the publisher has
	// a cert immediately; its rotation watcher is started below once the background
	// context exists. A failed load is fatal: an operator who configured a client
	// cert intends mTLS, and silently degrading would be rejected by an enforcing
	// policy-manager anyway.
	var (
		pmClientCertReloader *tlsreload.Reloader
		pmClientGetCert      func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	)
	if *policyManagerClientCertPath != "" && *policyManagerClientKeyPath != "" {
		pmClientCertReloader, err = tlsreload.New(*policyManagerClientCertPath, *policyManagerClientKeyPath, log.Named("pm-client-cert"))
		if err != nil {
			log.Fatal("Failed to load policy-manager client certificate", zap.Error(err))
		}
		pmClientGetCert = pmClientCertReloader.GetClientCertificate
	}
	pmClientTLS, err := config.BuildClientTLSConfig(*policyManagerCAPath, pmClientGetCert)
	if err != nil {
		log.Warn("policy-manager CA bundle unavailable; decision publisher falls back to system roots",
			zap.String("policy_manager_ca_path", *policyManagerCAPath),
			zap.Error(err),
		)
		pmClientTLS = nil
	}
	// Inter-service auth for the decisions channel (IAM-WU-11): when
	// --policy-manager-token-path is set, present the rotating projected
	// ServiceAccount token from that file (audience-bound, short TTL); it takes
	// precedence over the static env token. Empty keeps the legacy static-token
	// behavior (backward compatible). The mTLS wiring above is unchanged.
	pubOpts := []admission.Option{admission.WithTLSConfig(pmClientTLS)}
	if *policyManagerTokenPath != "" {
		pubOpts = append(pubOpts, admission.WithTokenFile(*policyManagerTokenPath))
		log.Info("decision publisher presents a projected ServiceAccount token (IAM-WU-11)",
			zap.String("token_path", *policyManagerTokenPath),
		)
	}
	publisher := admission.NewDecisionPublisher(pmURL, pmToken, log, metricsCollector, pubOpts...)
	defer publisher.Stop()

	// Initialize admission controller
	admissionController := admission.NewController(policyEngine, auditLogger, metricsCollector, log, publisher)

	// Rate-limiting / DoS-protection config (NET-WU-14, RES-WU-17). Flags
	// override the config-file values so an operator can tune limits without
	// editing the ConfigMap. The webhook is on the cluster's critical write
	// path; see config.RateLimitConfig for the defaults' rationale.
	rlCfg := cfg.Security.RateLimit
	if *rateLimitDisabled {
		rlCfg.Enabled = false
	}
	if *rateLimitRPS >= 0 {
		rlCfg.RequestsPerSecond = *rateLimitRPS
	}
	if *rateLimitBurst >= 0 {
		rlCfg.Burst = *rateLimitBurst
	}
	if *rateLimitMaxConcurrent >= 0 {
		rlCfg.MaxConcurrent = *rateLimitMaxConcurrent
	}
	if *rateLimitMaxBodyBytes >= 0 {
		rlCfg.MaxBodyBytes = *rateLimitMaxBodyBytes
	}

	// Setup webhook server. TLS parameters (min version, cipher suites,
	// client auth) are driven by cfg.Security.TLS rather than hardcoded
	// literals (CRY-WU-03). A startup failure here is fatal — serving on a
	// misconfigured TLS stack would be worse than not serving.
	webhookServer, err := setupWebhookServer(admissionController, &cfg.Security.TLS, *requireClientCert, rlCfg, metricsCollector, log)
	if err != nil {
		log.Fatal("Failed to build webhook TLS server", zap.Error(err))
	}

	// Background-process context. Canceled on SIGINT/SIGTERM below; the CRD
	// controllers and the TLS cert reloader stop when this is canceled.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Hot TLS certificate reload (CRY-WU-10): serve the cert via a
	// GetCertificate callback backed by a watcher so cert-manager / Secret
	// rotations are picked up without a pod restart. A failed initial load is
	// fatal — serving with no certificate is worse than not serving. Built
	// before the metrics server so its GetCertificate can back the metrics
	// listener too (CRY-WU-08) — one reloader, two listeners.
	certReloader, err := tlsreload.New(*certPath, *keyPath, log.Named("tls-reload"),
		tlsreload.WithOnReload(func(cert *tls.Certificate) {
			if cert != nil && cert.Leaf != nil {
				metricsCollector.SetCertExpiry("admission-webhook", cert.Leaf.NotAfter)
			}
		}))
	if err != nil {
		log.Fatal("Failed to load webhook TLS certificate", zap.Error(err))
	}
	webhookServer.TLSConfig.GetCertificate = certReloader.GetCertificate
	go func() {
		if startErr := certReloader.Start(ctx); startErr != nil {
			log.Error("TLS certificate reloader stopped with error", zap.Error(startErr))
		}
	}()

	// Start the policy-manager client-cert rotation watcher (IAM-WU-03) now that
	// the background context exists. The initial load already happened in
	// tlsreload.New above, so the publisher has been presenting a cert since
	// startup; this only keeps it fresh across cert-manager rotations.
	if pmClientCertReloader != nil {
		go func() {
			if startErr := pmClientCertReloader.Start(ctx); startErr != nil {
				log.Error("policy-manager client-cert reloader stopped with error", zap.Error(startErr))
			}
		}()
	}

	// Setup metrics server. When --metrics-tls is set (CRY-WU-08), the :9090
	// listener serves TLS 1.3 (reusing the same hot-reload serving cert) and
	// requires a bearer token on /metrics; /healthz stays open for probes.
	var (
		metricsTLSConf  *tls.Config
		metricsVerifier *auth.TokenVerifier
	)
	if *metricsTLS {
		metricsTLSConf, err = config.BuildServerTLSConfig(cfg.Security.TLS, nil)
		if err != nil {
			log.Fatal("Failed to build metrics TLS config", zap.Error(err))
		}
		metricsTLSConf.GetCertificate = certReloader.GetCertificate
		metricsVerifier = auth.NewTokenVerifier(
			os.Getenv("POLICY_MANAGER_INTERNAL_TOKEN"),
			os.Getenv("POLICY_MANAGER_INTERNAL_TOKEN_PREVIOUS"),
		)
	}
	// RES-WU-06 (CP-10, SC-5): TLS-aware readiness. webhookReady is flipped true
	// only once the :8443 TLS listener is bound (below) and back to false at the
	// start of graceful shutdown, so /readyz on the metrics server reflects REAL
	// admission-serving health — a pod whose TLS listener is down is pulled from
	// the Service endpoints instead of receiving (and fail-closed denying) calls.
	webhookReady := &atomic.Bool{}
	metricsServer := setupMetricsServer(metricsTLSConf, metricsVerifier, webhookReady)

	// Start servers
	go func() {
		log.Info("Starting metrics server", zap.Int("port", *metricsPort), zap.Bool("tls", *metricsTLS))
		var serr error
		if *metricsTLS {
			serr = metricsServer.ListenAndServeTLS("", "")
		} else {
			serr = metricsServer.ListenAndServe()
		}
		if serr != nil && serr != http.ErrServerClosed {
			log.Fatal("Failed to start metrics server", zap.Error(serr))
		}
	}()

	// RES-WU-06 (CP-10, SC-5): bind the webhook TLS listener SYNCHRONOUSLY so the
	// readiness gate reflects real serving health. Only after the socket is bound
	// do we flip webhookReady=true (the pod then joins the Service endpoints).
	// A bind failure is fatal — a webhook that cannot serve must never report
	// Ready. The TLS handshake/cert still come from TLSConfig.GetCertificate, so
	// ServeTLS is called with empty cert/key paths exactly like before.
	webhookListener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", webhookServer.Addr)
	if err != nil {
		log.Fatal("Failed to bind webhook server listener", zap.Int("port", *port), zap.Error(err))
	}
	webhookReady.Store(true)
	go func() {
		log.Info("Starting webhook server", zap.Int("port", *port))
		// Empty cert/key paths: the certificate is served via
		// TLSConfig.GetCertificate (the reloader), not a one-shot file read.
		if err := webhookServer.ServeTLS(webhookListener, "", ""); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start webhook server", zap.Error(err))
		}
	}()

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
		ns, err := policymanager.ResolvePodNamespace("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			log.Fatal("could not resolve pod namespace for leader election",
				zap.Error(err),
				zap.String("hint", "set POD_NAMESPACE env or run inside a Pod with a service-account token, or pass --disable-controllers to bypass the controller manager entirely"),
			)
		}
		opts := policymanager.ControllerOptions{
			// Distinct lease ID — when both policy-manager and webhook run
			// controllers in the same namespace, they must not contend over
			// the same leader-election lease.
			LeaderElectionID:        "kube-policies-admission-webhook",
			LeaderElectionNamespace: ns,
			PolicySink:              sink,
			// DisableLeaderElection: zero value (false) → election ENABLED at
			// the manager level. The Lease is still acquired so multi-replica
			// topology is observable externally (the e2e "exactly one
			// admission-webhook pod holds the lease" assertion). The
			// reconcilers themselves are flagged leaderless below.
			//
			// LeaderlessReconcilers=true is REQUIRED here: the PolicySink
			// feeds the local in-memory OPA engine. With LE-gated
			// reconcilers, only the leader's engine would receive Policy
			// CRD updates, and any admission request load-balanced to a
			// follower pod would bypass policy enforcement entirely.
			// Status-patch races between replicas are benign (every
			// replica writes the same Phase/Conditions for the same spec).
			LeaderlessReconcilers: true,
			// ExceptionSink wired via co-located reconciler — see plan §3.1 W2.
			// Same *exceptionSink instance is the engine's ExceptionRegistry
			// (read side); constructed above and passed to
			// policy.NewEngineWithExceptions. One struct, two named interfaces.
			ExceptionSink: excSink,
			// Bound the reconciler worker pool (RES-WU-17). <= 0 defers to the
			// package default (2).
			MaxConcurrentReconciles: *maxConcurrentReconciles,
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

	// RES-WU-06 / RES-WU-07 (CP-10, SC-5): flip readiness false FIRST so the
	// endpoints controller removes this pod from the Service, then KEEP SERVING
	// for the drain delay so the apiserver retargets healthy replicas before this
	// listener closes — avoiding fail-closed denials during a rolling restart /
	// scale-down. The webhook server is still up during this sleep (Shutdown is
	// called afterwards), so admission calls that race the endpoints update still
	// succeed here. Distroless/k8s<1.29-safe (no preStop sleep available).
	webhookReady.Store(false)
	if *shutdownDrainDelay > 0 {
		log.Info("draining before shutdown (RES-WU-07)", zap.Duration("delay", *shutdownDrainDelay))
		time.Sleep(*shutdownDrainDelay)
	}

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

	// AUD-WU-14 (AU-5/AU-9): flush the audit pipeline BEFORE exit so events for
	// in-flight requests (already drained by the webhook server shutdown above)
	// are persisted rather than lost on SIGTERM. Close drains the buffer, flushes
	// the backend, and is idempotent.
	if err := auditLogger.Close(); err != nil {
		log.Error("Failed to flush/close audit logger", zap.Error(err))
	}

	log.Info("Servers stopped")
}

func setupWebhookServer(controller *admission.Controller, tlsCfg *config.TLSConfig, requireClientCert bool, rlCfg config.RateLimitConfig, m middleware.Metrics, log *zap.Logger) (*http.Server, error) {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	// AUD-WU-01 (AU-3): distrust X-Forwarded-For so c.ClientIP() returns the real
	// TCP peer (the apiserver/proxy hop) and the audited source_ip cannot be
	// spoofed by a client-supplied forwarding header.
	if err := router.SetTrustedProxies(nil); err != nil {
		return nil, fmt.Errorf("failed to set trusted proxies: %w", err)
	}
	router.Use(gin.Recovery())

	// Health check endpoints. These are registered BEFORE the rate-limit
	// middleware group so the kubelet liveness/readiness probes (which run
	// constantly) are never throttled (NET-WU-14).
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	router.GET("/readyz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ready"})
	})

	// Rate-limiting / DoS-protection (NET-WU-14, RES-WU-17): a token-bucket rate
	// limit, an in-flight concurrency cap (429 on either), and a request-body
	// size cap (413). Applied ONLY to the admission endpoints — the health
	// probes above bypass it. Defaults are tuned to reject a flood without
	// throttling legitimate apiserver admission traffic; see config.RateLimitConfig.
	limiter := middleware.New(middleware.Config{
		RequestsPerSecond: rlCfg.RequestsPerSecond,
		Burst:             rlCfg.Burst,
		MaxConcurrent:     rlCfg.MaxConcurrent,
		MaxBodyBytes:      rlCfg.MaxBodyBytes,
		Enabled:           rlCfg.Enabled,
	}, m)
	log.Info("webhook rate-limiting configured",
		zap.Bool("enabled", rlCfg.Enabled),
		zap.Float64("requests_per_second", rlCfg.RequestsPerSecond),
		zap.Int("burst", rlCfg.Burst),
		zap.Int("max_concurrent", rlCfg.MaxConcurrent),
		zap.Int64("max_body_bytes", rlCfg.MaxBodyBytes),
	)

	// Admission webhook endpoints, guarded by the rate-limit middleware.
	admissionGroup := router.Group("", limiter.RequestMiddleware())
	admissionGroup.POST("/validate", controller.ValidateHandler)
	admissionGroup.POST("/mutate", controller.MutateHandler)

	// Build the TLS config from configuration rather than hardcoded literals
	// (CRY-WU-03). Apiserver client-certificate verification (mTLS, CRY-WU-04 /
	// IAM-WU-06) is ENFORCE-BY-DEFAULT: requireClientCert defaults true, so the
	// webhook fails closed unless a client-CA bundle is supplied and the listener
	// requires + verifies the apiserver client cert. requireClientCert=false is a
	// documented break-glass that restores the permissive (server-auth-only) path.
	clientCAs, err := config.LoadClientCAPool(tlsCfg.ClientCAPath)
	if err != nil {
		return nil, fmt.Errorf("load client CA bundle: %w", err)
	}

	// Fail-closed boundary (IAM-WU-06): enforcement is requested but no client-CA
	// bundle exists to verify against. Refuse to serve rather than silently
	// downgrading to a permissive listener — an enforce-intent webhook that
	// accepts uncerted callers is a security regression.
	if requireClientCert && clientCAs == nil {
		return nil, fmt.Errorf("client certificate verification is required (--require-client-cert=true) but no client-CA bundle was provided via --client-ca-path / security.tls.client_ca_path; supply the apiserver client-CA bundle, or set --require-client-cert=false as a documented break-glass")
	}

	tlsConf, err := config.BuildServerTLSConfig(*tlsCfg, clientCAs)
	if err != nil {
		return nil, err
	}

	if requireClientCert {
		// Honor enforcement regardless of the config's client_auth string: even if
		// tlsCfg.ClientAuth is not "require" (so BuildServerTLSConfig left ClientAuth
		// at request/none), FORCE RequireAndVerifyClientCert + the loaded pool so
		// --require-client-cert=true is authoritative. clientCAs is guaranteed
		// non-nil here (the fail-closed check above returned otherwise).
		tlsConf.ClientCAs = clientCAs
		tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
		log.Info("webhook TLS configured (apiserver mTLS ENFORCED)",
			zap.String("min_version", tlsCfg.MinVersion),
			zap.Strings("cipher_suites", tlsCfg.CipherSuites),
			zap.String("client_auth", tlsCfg.ClientAuth),
			zap.String("client_ca_path", tlsCfg.ClientCAPath),
			zap.Bool("mtls_enforced", true),
		)
	} else {
		// Break-glass: apiserver client-certificate verification is DISABLED. Keep
		// the permissive (server-auth-only) listener and warn LOUDLY so an operator
		// cannot miss that mTLS is off. If a CA bundle happens to be supplied, still
		// stay permissive (NoClientCert) — break-glass means "do not require a
		// client cert". BuildServerTLSConfig already left ClientAuth permissive when
		// no pool was loaded; force NoClientCert to be explicit even if a pool was.
		tlsConf.ClientAuth = tls.NoClientCert
		tlsConf.ClientCAs = nil
		log.Warn("BREAK-GLASS: apiserver client-certificate verification is DISABLED (--require-client-cert=false); the webhook will accept admission calls from ANY in-cluster client able to reach :8443. Set --require-client-cert=true and supply a client-CA bundle to fail closed.",
			zap.String("client_ca_path", tlsCfg.ClientCAPath),
			zap.Bool("mtls_enforced", false),
		)
	}

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", *port),
		Handler:      router,
		TLSConfig:    tlsConf,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return server, nil
}

// setupMetricsServer builds the :9090 metrics server. When tlsConf is non-nil
// the server serves TLS and /metrics is wrapped with bearer-token auth
// (CRY-WU-08); /healthz and /readyz are always left open so kubelet probes
// (which send no Authorization header) keep working. A nil tlsConf/verifier
// yields the legacy plain-HTTP, unauthenticated server.
//
// ready (RES-WU-06, CP-10/SC-5) backs the TLS-aware /readyz endpoint: /healthz
// is liveness (the process is up and the metrics listener answers), while
// /readyz returns 503 until the webhook's :8443 TLS listener is actually bound
// and again during graceful drain. A nil ready pointer makes /readyz behave
// like /healthz (always ready) for callers/tests that do not wire the gate.
func setupMetricsServer(tlsConf *tls.Config, verifier *auth.TokenVerifier, ready *atomic.Bool) *http.Server {
	mux := http.NewServeMux()
	metricsHandler := promhttp.Handler()
	if verifier != nil {
		metricsHandler = auth.RequireBearer(verifier, metricsHandler)
	}
	mux.Handle("/metrics", metricsHandler)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	// RES-WU-06 (CP-10, SC-5): readiness reflects the real :8443 TLS listener.
	// A down/unbound webhook listener makes this return 503 so the kubelet marks
	// the pod NotReady and the apiserver stops dialing it for admission.
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if ready == nil || ready.Load() {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("OK"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("not ready"))
	})

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", *metricsPort),
		Handler:      mux,
		TLSConfig:    tlsConf,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	return server
}
