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

	// CSPUnsafeInlineStyle appends 'unsafe-inline' to the CSP style-src
	// directive. Set this only if your built SPA injects inline styles
	// (e.g. some Tailwind v4 modes). The empirical verdict for the
	// shipped SPA build lives in web/CSP_VERDICT.md.
	CSPUnsafeInlineStyle bool

	// PolicyManagerStreamURL is the upstream SSE endpoint the dashboard
	// subscribes to for live decision events. A single connection is
	// maintained per dashboard process and fanned out to all browser clients.
	PolicyManagerStreamURL string
}

// LoadConfig reads dashboard configuration from environment variables.
//
// Defaults match the in-cluster service names produced by the Helm chart.
func LoadConfig() (*Config, error) {
	return &Config{
		PolicyManagerURL:           envOr("POLICY_MANAGER_URL", "http://policy-manager:8080"),
		PolicyManagerMetricsURL:    envOr("POLICY_MANAGER_METRICS_URL", "http://policy-manager:9091/metrics"),
		AdmissionWebhookMetricsURL: envOr("ADMISSION_WEBHOOK_METRICS_URL", "http://admission-webhook:9090/metrics"),
		AllowWrites:                envBool("ALLOW_WRITES", false),
		InternalToken:              os.Getenv("INTERNAL_TOKEN"),
		CSPUnsafeInlineStyle:       envBool("DASHBOARD_CSP_UNSAFE_INLINE_STYLE", false),
		PolicyManagerStreamURL:     envOr("POLICY_MANAGER_STREAM_URL", "http://policy-manager:8080/api/v1/decisions/stream"),
	}, nil
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
