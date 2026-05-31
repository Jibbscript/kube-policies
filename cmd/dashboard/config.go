package main

import (
	"os"
	"strconv"
	"strings"
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

	// PolicyManagerCAPath is the PEM CA bundle trusted when the dashboard
	// connects to the (TLS 1.3) policy-manager API and SSE stream (CRY-WU-07).
	// Empty falls back to system roots; the chart mounts the policy-manager
	// serving CA here.
	PolicyManagerCAPath string

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
}

// LoadConfig reads dashboard configuration from environment variables.
//
// Defaults match the in-cluster service names produced by the Helm chart.
func LoadConfig() (*Config, error) {
	return &Config{
		// The policy-manager API/stream serve TLS 1.3 (CRY-WU-05); default to
		// https. The metrics endpoints stay http until CRY-WU-08.
		PolicyManagerURL:           envOr("POLICY_MANAGER_URL", "https://policy-manager:8080"),
		PolicyManagerMetricsURL:    envOr("POLICY_MANAGER_METRICS_URL", "http://policy-manager:9091/metrics"),
		AdmissionWebhookMetricsURL: envOr("ADMISSION_WEBHOOK_METRICS_URL", "http://admission-webhook:9090/metrics"),
		AllowWrites:                envBool("ALLOW_WRITES", false),
		InternalToken:              os.Getenv("INTERNAL_TOKEN"),
		InternalTokenPrevious:      os.Getenv("INTERNAL_TOKEN_PREVIOUS"),
		CSPUnsafeInlineStyle:       envBool("DASHBOARD_CSP_UNSAFE_INLINE_STYLE", false),
		PolicyManagerStreamURL:     envOr("POLICY_MANAGER_STREAM_URL", "https://policy-manager:8080/api/v1/decisions/stream"),
		PolicyManagerCAPath:        os.Getenv("POLICY_MANAGER_CA_PATH"),
		TLSEnabled:                 envBool("DASHBOARD_TLS_ENABLED", false),
		CertPath:                   envOr("DASHBOARD_CERT_PATH", "/etc/dashboard-certs/tls.crt"),
		KeyPath:                    envOr("DASHBOARD_KEY_PATH", "/etc/dashboard-certs/tls.key"),
		HSTSEnabled:                envBool("DASHBOARD_HSTS_ENABLED", false),
		HSTSMaxAge:                 envIntOr("DASHBOARD_HSTS_MAX_AGE", 31536000),
		HSTSIncludeSubdomains:      envBool("DASHBOARD_HSTS_INCLUDE_SUBDOMAINS", true),
	}, nil
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
