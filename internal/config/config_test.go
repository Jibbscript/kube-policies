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

func TestLoadConfig_AuthEnabledRequiresIssuerJWKSAudience(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name: "empty issuer",
			body: `
security:
  authentication:
    enabled: true
    jwks_url: https://issuer.example.com/jwks
    audience: ["kube-policies-api"]
`,
			wantErr: "issuer is required",
		},
		{
			name: "empty jwks_url",
			body: `
security:
  authentication:
    enabled: true
    issuer: https://issuer.example.com
    audience: ["kube-policies-api"]
`,
			wantErr: "jwks_url is required",
		},
		{
			name: "empty audience",
			body: `
security:
  authentication:
    enabled: true
    issuer: https://issuer.example.com
    jwks_url: https://issuer.example.com/jwks
`,
			wantErr: "audience must list at least one",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearConfigEnv(t)
			path := filepath.Join(t.TempDir(), "config.yaml")
			writeConfig(t, path, tc.body)
			_, err := LoadConfig(path)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestLoadConfig_RejectsInvalidRBACRoles(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name: "invalid role binding role",
			body: `
security:
  rbac:
    role_bindings:
      - role: superuser
        groups: ["platform"]
`,
			wantErr: "role_bindings[0].role",
		},
		{
			name: "invalid default role",
			body: `
security:
  rbac:
    default_role: superuser
`,
			wantErr: "default_role",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearConfigEnv(t)
			path := filepath.Join(t.TempDir(), "config.yaml")
			writeConfig(t, path, tc.body)
			_, err := LoadConfig(path)
			require.Error(t, err)
			require.Contains(t, err.Error(), tc.wantErr)
		})
	}
}

func TestLoadConfig_AuthEnabledDefaultsSupportedAlgsToFIPSAsymmetricSet(t *testing.T) {
	clearConfigEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfig(t, path, `
security:
  authentication:
    enabled: true
    issuer: https://issuer.example.com
    jwks_url: https://issuer.example.com/jwks
    audience: ["kube-policies-api"]
`)

	cfg, err := LoadConfig(path)
	require.NoError(t, err)

	require.ElementsMatch(t, fipsAsymmetricAlgs, cfg.Security.Authentication.SupportedAlgs)
	require.NotContains(t, cfg.Security.Authentication.SupportedAlgs, "HS256")
	require.NotContains(t, cfg.Security.Authentication.SupportedAlgs, "none")
	// Claim-name defaults fill in too when auth is enabled.
	require.Equal(t, "sub", cfg.Security.Authentication.UsernameClaim)
	require.Equal(t, "groups", cfg.Security.Authentication.GroupsClaim)
}

func TestLoadConfig_AuthDisabledLeavesZeroValue(t *testing.T) {
	clearConfigEnv(t)
	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "missing.yaml"))
	require.NoError(t, err)

	require.False(t, cfg.Security.Authentication.Enabled)
	require.Empty(t, cfg.Security.Authentication.SupportedAlgs)
	require.Empty(t, cfg.Security.Authentication.UsernameClaim)
	require.Empty(t, cfg.Security.Authentication.GroupsClaim)
}

func writeConfig(t *testing.T, path string, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(strings.TrimSpace(body)+"\n"), 0o600))
}
