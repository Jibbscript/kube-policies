package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func clearConfigEnv(t *testing.T) {
	t.Helper()
	keys := []string{
		"KUBE_POLICIES_SERVER_PORT",
		"KUBE_POLICIES_SERVER_METRICS_PORT",
		"KUBE_POLICIES_SERVER_LOG_LEVEL",
		"KUBE_POLICIES_SERVER_TLS_CERT_PATH",
		"KUBE_POLICIES_SERVER_TLS_KEY_PATH",
		"KUBE_POLICIES_POLICY_FAILURE_MODE",
		"KUBE_POLICIES_POLICY_DISABLE_DEFAULTS",
		"KUBE_POLICIES_AUDIT_ENABLED",
		"KUBE_POLICIES_AUDIT_BACKEND",
		"KUBE_POLICIES_AUDIT_BUFFER_SIZE",
		"KUBE_POLICIES_AUDIT_FLUSH_INTERVAL",
		"KUBE_POLICIES_AUDIT_RETENTION",
		"KUBE_POLICIES_METRICS_ENABLED",
		"KUBE_POLICIES_METRICS_NAMESPACE",
		"KUBE_POLICIES_METRICS_SUBSYSTEM",
		"KUBE_POLICIES_SECURITY_TLS_MIN_VERSION",
		"KUBE_POLICIES_SECURITY_TLS_CLIENT_AUTH",
		"KUBE_POLICIES_SECURITY_RBAC_ENABLED",
		"KUBE_POLICIES_SECURITY_ENCRYPTION_AT_REST_ENABLED",
		"KUBE_POLICIES_SECURITY_ENCRYPTION_AT_REST_ALGORITHM",
		"KUBE_POLICIES_SECURITY_ENCRYPTION_IN_TRANSIT_ENABLED",
		"KUBE_POLICIES_SECURITY_ENCRYPTION_IN_TRANSIT_MODE",
		"KUBE_POLICIES_STORAGE_TYPE",
	}
	for _, key := range keys {
		t.Setenv(key, "")
	}
}

func TestLoadConfig_DefaultsAndMissingFile(t *testing.T) {
	clearConfigEnv(t)

	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	require.NoError(t, err)

	require.Equal(t, 8443, cfg.Server.Port)
	require.Equal(t, 9090, cfg.Server.MetricsPort)
	require.Equal(t, "fail-closed", cfg.Policy.FailureMode)
	require.False(t, cfg.Policy.DisableDefaults)
	require.Equal(t, "file", cfg.Audit.Backend)
	require.Equal(t, "1.3", cfg.Security.TLS.MinVersion)
}

func TestLoadConfig_EnvironmentOverridesNestedKeys(t *testing.T) {
	clearConfigEnv(t)
	t.Setenv("KUBE_POLICIES_SERVER_PORT", "9443")
	t.Setenv("KUBE_POLICIES_POLICY_FAILURE_MODE", "fail-open")
	t.Setenv("KUBE_POLICIES_POLICY_DISABLE_DEFAULTS", "true")
	t.Setenv("KUBE_POLICIES_AUDIT_BACKEND", "stdout")
	t.Setenv("KUBE_POLICIES_SECURITY_TLS_MIN_VERSION", "1.3")

	cfg, err := LoadConfig("")
	require.NoError(t, err)

	require.Equal(t, 9443, cfg.Server.Port)
	require.Equal(t, "fail-open", cfg.Policy.FailureMode)
	require.True(t, cfg.Policy.DisableDefaults)
	require.Equal(t, "stdout", cfg.Audit.Backend)
}

func TestLoadConfig_RejectsUnsupportedAuditBackend(t *testing.T) {
	clearConfigEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfig(t, path, `
audit:
  enabled: true
  backend: elasticsearch
`)

	_, err := LoadConfig(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid audit backend")
}

func TestLoadConfig_RejectsTLSBelowTLS13(t *testing.T) {
	clearConfigEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfig(t, path, `
security:
  tls:
    min_version: "1.2"
`)

	_, err := LoadConfig(path)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid TLS min version")
}

func writeConfig(t *testing.T, path string, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(strings.TrimSpace(body)+"\n"), 0o600))
}
