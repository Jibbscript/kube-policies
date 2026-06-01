package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the runtime configuration for the dashboard binary.
//
// All fields are env-driven; there is no file IO at startup. The dashboard
// is intentionally a thin BFF — sensitive policy data and writes are gated
// here, so configuration is kept narrow and auditable.
type Config struct {
	// PolicyManagerURL is the base URL for the upstream policy-manager API
	// (reverse-proxied at /api/v1/*).
	PolicyManagerURL string

	// PolicyManagerMetricsURL is the /metrics endpoint scraped for the
	// /api/metrics/summary aggregation.
	PolicyManagerMetricsURL string

	// AdmissionWebhookMetricsURL is the /metrics endpoint scraped for the
	// admission webhook side of the /api/metrics/summary aggregation.
	AdmissionWebhookMetricsURL string

	// AllowWrites gates write verbs (POST/PUT/PATCH/DELETE) through the
	// reverse proxy. Default false: the dashboard is read-only by default.
	AllowWrites bool

	// InternalToken is the shared secret required on POST
	// /api/decisions/internal. If empty, the endpoint always returns 401.
	InternalToken string

	// InternalTokenPrevious is the prior internal token, accepted alongside
	// InternalToken during a zero-downtime rotation window (CRY-WU-14). Empty
	// outside of a rotation.
	InternalTokenPrevious string

	// CSPUnsafeInlineStyle appends 'unsafe-inline' to the CSP style-src
	// directive. Set this only if your built SPA injects inline styles
	// (e.g. some Tailwind v4 modes). The empirical verdict for the
	// shipped SPA build lives in web/CSP_VERDICT.md.
	CSPUnsafeInlineStyle bool

	// PolicyManagerStreamURL is the upstream SSE endpoint the dashboard
	// subscribes to for live decision events. A single connection is
	// maintained per dashboard process and fanned out to all browser clients.
	PolicyManagerStreamURL string

	// StreamTokenPath is the in-pod path of a projected ServiceAccount token
	// (audience=policy-manager, short-TTL, kubelet-rotated) the dashboard presents
	// on the upstream SSE subscription so the policy-manager's TokenReview gate on
	// /api/v1/decisions/stream + /recent accepts it (IAM-WU-11, Inc7 Stream A).
	// Set in tokenreview mode; the file is re-read per connect to follow rotation.
	// Empty in static mode (StreamToken is used instead) or in dev (no token; the
	// subscriber simply omits the Authorization header and backs off on 401).
	StreamTokenPath string

	// StreamToken is the static shared bearer presented on the upstream SSE
	// subscription in static mode (IAM-WU-11 escape hatch), the same trust domain
	// as the webhook's static internal token. Ignored when StreamTokenPath is set
	// (the projected token takes precedence). Empty leaves the subscription
	// unauthenticated (dev posture).
	StreamToken string

	// PolicyManagerCAPath is the PEM CA bundle trusted when the dashboard
	// connects to the (TLS 1.3) policy-manager API and SSE stream (CRY-WU-07).
	// Empty falls back to system roots; the chart mounts the policy-manager
	// serving CA here. It also verifies the webhook/policy-manager metrics
	// endpoints when those serve TLS (CRY-WU-08; in cert-manager mode all three
	// share one issuer CA).
	PolicyManagerCAPath string

	// MetricsToken is the bearer token presented when scraping the webhook /
	// policy-manager /metrics endpoints if they require auth (CRY-WU-08). It is
	// the shared internal token; sent only over https so it never crosses a
	// plaintext metrics scrape.
	MetricsToken string

	// PolicyManagerClientCertPath / PolicyManagerClientKeyPath, when BOTH set,
	// make the dashboard PRESENT a client certificate to the policy-manager for
	// mutual TLS (IAM-WU-03) on the reverse-proxied API and the SSE stream —
	// authenticating the dashboard as a service caller when the policy-manager
	// enforces --require-client-cert. Empty disables client-cert presentation. The
	// metrics scraper does not present a client cert (the metrics listeners use
	// bearer auth, not mTLS).
	PolicyManagerClientCertPath string
	PolicyManagerClientKeyPath  string

	// TLSEnabled makes the dashboard serve its API (:8090) and metrics (:9092)
	// over TLS 1.3 (CRY-WU-07). Default false: the common topology terminates
	// TLS at the Ingress, where the pod sees plaintext. Set true to terminate
	// TLS in-pod.
	TLSEnabled bool
	// CertPath / KeyPath are the in-pod TLS cert/key (used only when TLSEnabled).
	CertPath string
	KeyPath  string

	// HSTSEnabled emits a Strict-Transport-Security header (CRY-WU-07). Gated
	// independently of TLSEnabled because HSTS is correct whenever the
	// browser-facing hop is HTTPS (typically the Ingress), regardless of whether
	// the pod itself terminates TLS. Leave off if the Ingress already emits HSTS
	// to avoid a conflicting max-age.
	HSTSEnabled           bool
	HSTSMaxAge            int
	HSTSIncludeSubdomains bool

	// --- User authentication (IAM-WU-04 / NET-WU-18 / IAM-WU-16) ---

	// AuthMode selects dashboard user authentication: "disabled" (default; the
	// legacy unauthenticated dev posture), "oidc" (Authorization Code + PKCE login
	// in the BFF with a sealed session cookie), or "forward-auth" (trust identity
	// headers from an upstream identity-aware proxy).
	AuthMode string

	// OIDC* configure the "oidc" mode. Issuer/ClientID/ClientSecret/RedirectURL +
	// SessionKey are required when AuthMode=oidc (LoadConfig fails closed otherwise).
	OIDCIssuer        string
	OIDCClientID      string
	OIDCClientSecret  string
	OIDCRedirectURL   string
	OIDCScopes        []string
	OIDCUsernameClaim string
	OIDCGroupsClaim   string

	// SessionKey / SessionKeyPrevious are base64-encoded 32-byte AES-256 keys that
	// seal the session cookie; the previous key is accepted during rotation.
	SessionKey         string
	SessionKeyPrevious string

	// SessionIdleTimeout / SessionAbsoluteTimeout bound the session per FedRAMP
	// AC-11/AC-12 (defaults 15m idle, 12h absolute).
	SessionIdleTimeout     time.Duration
	SessionAbsoluteTimeout time.Duration

	// SessionCookieInsecure drops the Secure attribute + __Host- prefix on the
	// session cookies for plaintext local development. Default false (secure).
	SessionCookieInsecure bool

	// ForwardAuth*Header name the trusted identity headers in "forward-auth" mode
	// (defaults match oauth2-proxy: X-Forwarded-User/Email/Groups/Access-Token).
	ForwardAuthUserHeader   string
	ForwardAuthEmailHeader  string
	ForwardAuthGroupsHeader string
	ForwardAuthTokenHeader  string
}

// LoadConfig reads dashboard configuration from environment variables.
//
// Defaults match the in-cluster service names produced by the Helm chart.
func LoadConfig() (*Config, error) {
	cfg := &Config{
		// The policy-manager API/stream serve TLS 1.3 (CRY-WU-05); default to
		// https. The metrics-URL defaults are http; the chart flips them to
		// https when metrics.tls.enabled (CRY-WU-08) and supplies the scrape token.
		PolicyManagerURL:           envOr("POLICY_MANAGER_URL", "https://policy-manager:8080"),
		PolicyManagerMetricsURL:    envOr("POLICY_MANAGER_METRICS_URL", "http://policy-manager:9091/metrics"),
		AdmissionWebhookMetricsURL: envOr("ADMISSION_WEBHOOK_METRICS_URL", "http://admission-webhook:9090/metrics"),
		AllowWrites:                envBool("ALLOW_WRITES", false),
		InternalToken:              os.Getenv("INTERNAL_TOKEN"),
		InternalTokenPrevious:      os.Getenv("INTERNAL_TOKEN_PREVIOUS"),
		CSPUnsafeInlineStyle:       envBool("DASHBOARD_CSP_UNSAFE_INLINE_STYLE", false),
		PolicyManagerStreamURL:     envOr("POLICY_MANAGER_STREAM_URL", "https://policy-manager:8080/api/v1/decisions/stream"),
		StreamTokenPath:            os.Getenv("POLICY_MANAGER_STREAM_TOKEN_PATH"),
		// Default to the shared internal token env so a static-mode deployment
		// that already provides POLICY_MANAGER_INTERNAL_TOKEN authenticates the
		// SSE subscription without a second secret; POLICY_MANAGER_STREAM_TOKEN
		// overrides it when set.
		StreamToken:                 envOr("POLICY_MANAGER_STREAM_TOKEN", os.Getenv("POLICY_MANAGER_INTERNAL_TOKEN")),
		PolicyManagerCAPath:         os.Getenv("POLICY_MANAGER_CA_PATH"),
		MetricsToken:                os.Getenv("POLICY_MANAGER_INTERNAL_TOKEN"),
		PolicyManagerClientCertPath: os.Getenv("POLICY_MANAGER_CLIENT_CERT_PATH"),
		PolicyManagerClientKeyPath:  os.Getenv("POLICY_MANAGER_CLIENT_KEY_PATH"),
		TLSEnabled:                  envBool("DASHBOARD_TLS_ENABLED", false),
		CertPath:                    envOr("DASHBOARD_CERT_PATH", "/etc/dashboard-certs/tls.crt"),
		KeyPath:                     envOr("DASHBOARD_KEY_PATH", "/etc/dashboard-certs/tls.key"),
		HSTSEnabled:                 envBool("DASHBOARD_HSTS_ENABLED", false),
		HSTSMaxAge:                  envIntOr("DASHBOARD_HSTS_MAX_AGE", 31536000),
		HSTSIncludeSubdomains:       envBool("DASHBOARD_HSTS_INCLUDE_SUBDOMAINS", true),

		AuthMode:                envOr("DASHBOARD_AUTH_MODE", "disabled"),
		OIDCIssuer:              os.Getenv("DASHBOARD_OIDC_ISSUER"),
		OIDCClientID:            os.Getenv("DASHBOARD_OIDC_CLIENT_ID"),
		OIDCClientSecret:        os.Getenv("DASHBOARD_OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:         os.Getenv("DASHBOARD_OIDC_REDIRECT_URL"),
		OIDCScopes:              splitScopes(envOr("DASHBOARD_OIDC_SCOPES", "openid profile email groups")),
		OIDCUsernameClaim:       envOr("DASHBOARD_OIDC_USERNAME_CLAIM", "sub"),
		OIDCGroupsClaim:         envOr("DASHBOARD_OIDC_GROUPS_CLAIM", "groups"),
		SessionKey:              os.Getenv("DASHBOARD_SESSION_KEY"),
		SessionKeyPrevious:      os.Getenv("DASHBOARD_SESSION_KEY_PREVIOUS"),
		SessionIdleTimeout:      envDurationOr("DASHBOARD_SESSION_IDLE_TIMEOUT", 15*time.Minute),
		SessionAbsoluteTimeout:  envDurationOr("DASHBOARD_SESSION_ABSOLUTE_TIMEOUT", 12*time.Hour),
		SessionCookieInsecure:   envBool("DASHBOARD_SESSION_COOKIE_INSECURE", false),
		ForwardAuthUserHeader:   envOr("DASHBOARD_FORWARD_AUTH_USER_HEADER", "X-Forwarded-User"),
		ForwardAuthEmailHeader:  envOr("DASHBOARD_FORWARD_AUTH_EMAIL_HEADER", "X-Forwarded-Email"),
		ForwardAuthGroupsHeader: envOr("DASHBOARD_FORWARD_AUTH_GROUPS_HEADER", "X-Forwarded-Groups"),
		ForwardAuthTokenHeader:  envOr("DASHBOARD_FORWARD_AUTH_TOKEN_HEADER", "X-Forwarded-Access-Token"),
	}
	if err := cfg.validateAuth(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// validateAuth fails closed when oidc mode is selected without the credentials
// it needs, so a half-configured deployment refuses to start rather than serving
// an unprotected dashboard while claiming auth is on.
func (c *Config) validateAuth() error {
	switch c.AuthMode {
	case "", "disabled", "forward-auth":
		return nil
	case "oidc":
		var missing []string
		if c.OIDCIssuer == "" {
			missing = append(missing, "DASHBOARD_OIDC_ISSUER")
		}
		if c.OIDCClientID == "" {
			missing = append(missing, "DASHBOARD_OIDC_CLIENT_ID")
		}
		if c.OIDCClientSecret == "" {
			missing = append(missing, "DASHBOARD_OIDC_CLIENT_SECRET")
		}
		if c.OIDCRedirectURL == "" {
			missing = append(missing, "DASHBOARD_OIDC_REDIRECT_URL")
		}
		if c.SessionKey == "" {
			missing = append(missing, "DASHBOARD_SESSION_KEY")
		}
		if len(missing) > 0 {
			return fmt.Errorf("DASHBOARD_AUTH_MODE=oidc requires: %s", strings.Join(missing, ", "))
		}
		return nil
	default:
		return fmt.Errorf("invalid DASHBOARD_AUTH_MODE %q (want disabled|oidc|forward-auth)", c.AuthMode)
	}
}

// splitScopes splits a space-separated OIDC scope list, dropping empties.
func splitScopes(raw string) []string {
	out := []string{}
	for _, s := range strings.Fields(raw) {
		out = append(out, s)
	}
	return out
}

// envDurationOr parses a Go duration (e.g. "15m", "12h") from key, or returns
// fallback when unset/invalid.
func envDurationOr(key string, fallback time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return fallback
	}
	d, err := time.ParseDuration(strings.TrimSpace(v))
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

// envIntOr returns the integer value of key, or fallback when unset/invalid.
func envIntOr(key string, fallback int) int {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return fallback
	}
	return n
}

func envOr(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return fallback
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off":
		return false
	}
	// Be permissive; strconv.ParseBool handles the rest, default false.
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}
