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

	"go.uber.org/zap"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/Jibbscript/kube-policies/internal/auth"
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
	// metricsTLS serves the :9091 metrics endpoint over TLS 1.3 with bearer-token
	// auth on /metrics (CRY-WU-08); /healthz + /readyz stay open. Default off.
	metricsTLS = flag.Bool("metrics-tls", false, "Serve /metrics over TLS 1.3 with bearer-token auth (CRY-WU-08)")

	// clientCAPath enables OPTIONAL mutual TLS on the :8080 API (IAM-WU-03): when
	// set, the policy-manager verifies a client certificate presented by the
	// service callers (admission-webhook decision publisher, dashboard proxy/SSE)
	// against this PEM client-CA bundle. The flag overrides the config-file
	// security.tls.client_ca_path. Empty disables client-cert verification.
	clientCAPath = flag.String("client-ca-path", "", "Path to PEM client-CA bundle for policy-manager API mTLS (IAM-WU-03); empty disables client-cert verification")

	// requireClientCert makes API mTLS ENFORCING: the listener requires + verifies
	// the client certificate (RequireAndVerifyClientCert) regardless of the
	// config's client_auth string. Default FALSE (optional mTLS) — unlike the
	// admission webhook (enforce-by-default, IAM-WU-06), the management API is also
	// reachable by human operators and the OIDC/bearer layers already authenticate
	// it, so mTLS is defense-in-depth that operators opt into. When true, a
	// client-CA bundle MUST be supplied via --client-ca-path /
	// security.tls.client_ca_path or startup fails closed.
	requireClientCert = flag.Bool("require-client-cert", false, "Require + verify a client certificate (mTLS) on the API listener (IAM-WU-03). Default false (optional). When true a client-CA bundle must be supplied or startup fails closed.")

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
	metricsCollector := metrics.NewCollector()

	// Initialize policy manager
	policyManager, err := policymanager.NewManager(cfg, log)
	if err != nil {
		log.Fatal("Failed to initialize policy manager", zap.Error(err))
	}
	// Accept both the current and (during a rotation window) the previous
	// internal token so secret rotation causes no downtime (CRY-WU-14). This is
	// kept unconditionally so the static fallback is always available; in
	// tokenreview mode it is only consulted on a clean negative TokenReview
	// verdict (see Manager.IngestInternal).
	policyManager.SetInternalTokens(
		os.Getenv("POLICY_MANAGER_INTERNAL_TOKEN"),
		os.Getenv("POLICY_MANAGER_INTERNAL_TOKEN_PREVIOUS"),
	)

	// Inter-service auth mode for the webhook -> policy-manager decisions channel
	// (IAM-WU-11). Default (unset env): tokenreview — BUT the default is
	// context-aware (see below). "static" is the documented escape hatch for
	// non-cluster/demo deployments. Any other value is an operator typo and fails
	// closed so misconfigured deployments are caught immediately (mirrors the Helm
	// enum guard in _helpers.tpl).
	internalAuthModeRaw := os.Getenv("POLICY_MANAGER_INTERNAL_AUTH_MODE")
	internalAuthModeExplicit := internalAuthModeRaw != "" // operator set it explicitly
	internalAudience := os.Getenv("POLICY_MANAGER_INTERNAL_AUDIENCE")
	if internalAudience == "" {
		internalAudience = "policy-manager"
	}
	internalSubject := os.Getenv("POLICY_MANAGER_INTERNAL_SUBJECT")

	switch internalAuthModeRaw {
	case "static":
		// Static-only: shared bearer token, no TokenReview client needed.
		log.Warn("internal decisions channel auth: STATIC bearer token (IAM-WU-11 escape hatch). TokenReview validation is OFF; intended only for non-cluster/demo deployments. Set POLICY_MANAGER_INTERNAL_AUTH_MODE=tokenreview on a real cluster.")

	case "tokenreview", "":
		// Attempt to wire the TokenReview authenticator. Resolution order:
		//   1. ctrl.GetConfig() (--kubeconfig flag > KUBECONFIG env > in-cluster)
		//   2. kubernetes.NewForConfig()
		// On failure:
		//   - EXPLICIT tokenreview (env set) → log.Fatal (operator demanded secure
		//     mode; fail closed, never silent-downgrade).
		//   - DEFAULT (env unset) → log.Warn and fall back to static-only so a
		//     previously-working API-only run (--disable-controllers + static token,
		//     no kubeconfig) is not broken by the Inc5 default change.
		restCfg, cfgErr := ctrl.GetConfig()
		if cfgErr != nil {
			if internalAuthModeExplicit {
				log.Fatal("could not resolve a Kubernetes config for TokenReview validation (POLICY_MANAGER_INTERNAL_AUTH_MODE=tokenreview was set explicitly — fail closed, IAM-WU-11)",
					zap.Error(cfgErr),
					zap.String("hint", "run inside a Pod with a service-account token, set --kubeconfig=PATH, or set POLICY_MANAGER_INTERNAL_AUTH_MODE=static for non-cluster/demo deployments"),
				)
			}
			log.Warn("internal decisions channel auth: TokenReview unavailable (no kube client); defaulting to static bearer token. Set POLICY_MANAGER_INTERNAL_AUTH_MODE=tokenreview explicitly once a kubeconfig is available, or POLICY_MANAGER_INTERNAL_AUTH_MODE=static to silence this warning.",
				zap.Error(cfgErr),
			)
			break
		}
		cs, csErr := kubernetes.NewForConfig(restCfg)
		if csErr != nil {
			if internalAuthModeExplicit {
				log.Fatal("could not build a Kubernetes clientset for TokenReview validation (POLICY_MANAGER_INTERNAL_AUTH_MODE=tokenreview was set explicitly — fail closed, IAM-WU-11)",
					zap.Error(csErr),
				)
			}
			log.Warn("internal decisions channel auth: TokenReview unavailable (clientset build failed); defaulting to static bearer token.",
				zap.Error(csErr),
			)
			break
		}
		policyManager.SetInternalTokenReviewer(
			policymanager.NewInternalTokenAuthenticator(
				cs.AuthenticationV1().TokenReviews(),
				internalAudience,
				internalSubject,
				log.Named("internal-tokenreview"),
			),
		)
		log.Info("internal decisions channel auth: TokenReview (audience+subject-bound) ENABLED",
			zap.String("expected_audience", internalAudience),
			zap.String("expected_subject", internalSubject),
		)

	default:
		// Unknown value → operator typo → fail closed. This mirrors the Helm
		// chart's enum guard (mode must be tokenreview or static).
		log.Fatal("invalid POLICY_MANAGER_INTERNAL_AUTH_MODE; must be one of: tokenreview, static",
			zap.String("value", internalAuthModeRaw),
		)
	}

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
	// Optional mutual TLS on the API listener (IAM-WU-03). An explicit
	// --client-ca-path overrides the config-file value; --require-client-cert is
	// the authoritative enforcement switch (mirrors the webhook, IAM-WU-06). The
	// branch logic lives in buildAPITLSConfig so it is unit-tested directly.
	if *clientCAPath != "" {
		cfg.Security.TLS.ClientCAPath = *clientCAPath
	}
	tlsConf, err := buildAPITLSConfig(cfg.Security.TLS, *requireClientCert)
	if err != nil {
		log.Fatal("Failed to build API TLS config", zap.Error(err))
	}
	switch tlsConf.ClientAuth {
	case tls.RequireAndVerifyClientCert:
		log.Info("policy-manager API mTLS ENFORCED (RequireAndVerifyClientCert)",
			zap.String("client_ca_path", cfg.Security.TLS.ClientCAPath),
			zap.Bool("mtls_enforced", true),
		)
	case tls.VerifyClientCertIfGiven:
		log.Info("policy-manager API optional mTLS (client-CA loaded; a presented client cert is verified, an absent cert is admitted)",
			zap.String("client_ca_path", cfg.Security.TLS.ClientCAPath),
		)
	}

	// OIDC bearer authN + RBAC for the management plane (IAM-WU-01/02). When
	// security.authentication.enabled is false the management API is served
	// unauthenticated — a tracked dev-only gap. NewOIDCVerifier only sets up a
	// lazy RemoteKeySet (no blocking network call); if it errors we fail closed.
	var apiVerifier policymanager.OIDCVerifier
	if cfg.Security.Authentication.Enabled {
		apiVerifier, err = policymanager.NewOIDCVerifier(ctx, cfg.Security.Authentication)
		if err != nil {
			log.Fatal("Failed to build OIDC verifier", zap.Error(err))
		}
	}
	log.Info("policy-manager API authentication configured",
		zap.Bool("oidc_enforced", cfg.Security.Authentication.Enabled),
		zap.String("issuer", cfg.Security.Authentication.Issuer),
		zap.Int("rbac_role_bindings", len(cfg.Security.RBAC.RoleBindings)),
	)
	if !cfg.Security.Authentication.Enabled {
		log.Warn("SECURITY: OIDC authentication is DISABLED — the policy-manager management API (/api/v1 policies/bundles/exceptions/compliance) is served UNAUTHENTICATED. This is a dev-only posture and a tracked gap; production deployments MUST set security.authentication.enabled=true with issuer/jwks_url/audience.")
	}
	certReloader, err := tlsreload.New(*certPath, *keyPath, log.Named("tls-reload"),
		tlsreload.WithOnReload(func(cert *tls.Certificate) {
			if cert != nil && cert.Leaf != nil {
				metricsCollector.SetCertExpiry("policy-manager", cert.Leaf.NotAfter)
			}
		}))
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
		Handler:      policymanager.NewAPIRouter(policyManager, cfg.Security.Authentication, cfg.Security.RBAC, apiVerifier),
		TLSConfig:    tlsConf,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	// When --metrics-tls is set (CRY-WU-08), the :9091 metrics endpoint serves
	// TLS 1.3 (reusing the same hot-reload serving cert) and requires a bearer
	// token on /metrics; /healthz + /readyz stay open for probes.
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
	metricsServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", *metricsPort),
		Handler:      policymanager.NewMetricsRouter(metricsVerifier),
		TLSConfig:    metricsTLSConf,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

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

// buildAPITLSConfig builds the policy-manager API (:8080) listener TLS config
// with OPTIONAL mutual TLS (IAM-WU-03). requireClientCert is authoritative over
// the config's client_auth string, mirroring the admission webhook (IAM-WU-06):
//
//   - requireClientCert=true → RequireAndVerifyClientCert; fails CLOSED with an
//     error when no client-CA bundle is configured (serving an enforce-intent
//     listener that cannot verify is worse than refusing to start).
//   - requireClientCert=false + a client-CA bundle present → VerifyClientCertIfGiven:
//     a presented client cert is verified against the CA, an absent one is
//     admitted. The shipped config default client_auth="require" must NOT be
//     allowed to silently lock out the OIDC/bearer-authenticated operators that
//     optional mode keeps serving, so an enforcing mode is downgraded here.
//   - requireClientCert=false + no bundle → server-auth only (BuildServerTLSConfig
//     downgrades a "require" config to NoClientCert when no pool is supplied).
func buildAPITLSConfig(tlsCfg config.TLSConfig, requireClientCert bool) (*tls.Config, error) {
	clientCAs, err := config.LoadClientCAPool(tlsCfg.ClientCAPath)
	if err != nil {
		return nil, fmt.Errorf("load client-CA bundle: %w", err)
	}
	if requireClientCert && clientCAs == nil {
		return nil, fmt.Errorf("client certificate verification is required (--require-client-cert=true) but no client-CA bundle was provided via --client-ca-path / security.tls.client_ca_path; supply the CA that signs the webhook/dashboard client certificates, or leave --require-client-cert=false (optional mTLS)")
	}
	tlsConf, err := config.BuildServerTLSConfig(tlsCfg, clientCAs)
	if err != nil {
		return nil, err
	}
	switch {
	case requireClientCert:
		// Authoritative enforce: force RequireAndVerifyClientCert regardless of the
		// config's client_auth. clientCAs is guaranteed non-nil (checked above).
		tlsConf.ClientCAs = clientCAs
		tlsConf.ClientAuth = tls.RequireAndVerifyClientCert
	case clientCAs != nil:
		// Optional mTLS: verify a presented cert, admit an absent one. The config
		// default client_auth="require" would otherwise enforce and lock out the
		// cert-less callers (human operators) that optional mode must keep serving.
		tlsConf.ClientAuth = tls.VerifyClientCertIfGiven
	}
	return tlsConf, nil
}
