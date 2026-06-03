package config

import (
	"crypto/tls"
	"crypto/x509"
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
		"KUBE_POLICIES_SECURITY_RATELIMIT_ENABLED",
		"KUBE_POLICIES_SECURITY_RATELIMIT_REQUESTS_PER_SECOND",
		"KUBE_POLICIES_SECURITY_RATELIMIT_BURST",
		"KUBE_POLICIES_SECURITY_RATELIMIT_MAX_CONCURRENT",
		"KUBE_POLICIES_SECURITY_RATELIMIT_MAX_BODY_BYTES",
		"KUBE_POLICIES_SECURITY_RATELIMIT_MAX_STREAM_CONNECTIONS",
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

	// Rate-limiting / DoS-protection defaults (NET-WU-14/15, RES-WU-17).
	rl := cfg.Security.RateLimit
	require.True(t, rl.Enabled)
	require.InDelta(t, 50.0, rl.RequestsPerSecond, 1e-9)
	require.Equal(t, 100, rl.Burst)
	require.Equal(t, 100, rl.MaxConcurrent)
	require.Equal(t, int64(3145728), rl.MaxBodyBytes)
	require.Equal(t, 100, rl.MaxStreamConnections)
}

func TestLoadConfig_RateLimitOverridesAndValidation(t *testing.T) {
	clearConfigEnv(t)

	// File override of the rate-limit stanza is honored.
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfig(t, path, `
security:
  ratelimit:
    enabled: false
    requests_per_second: 25.5
    burst: 40
    max_concurrent: 12
    max_body_bytes: 1048576
    max_stream_connections: 7
`)
	cfg, err := LoadConfig(path)
	require.NoError(t, err)
	rl := cfg.Security.RateLimit
	require.False(t, rl.Enabled)
	require.InDelta(t, 25.5, rl.RequestsPerSecond, 1e-9)
	require.Equal(t, 40, rl.Burst)
	require.Equal(t, 12, rl.MaxConcurrent)
	require.Equal(t, int64(1048576), rl.MaxBodyBytes)
	require.Equal(t, 7, rl.MaxStreamConnections)
}

func TestLoadConfig_RateLimitRejectsNegatives(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		wantErr string
	}{
		{
			name:    "negative requests_per_second",
			body:    "security:\n  ratelimit:\n    requests_per_second: -1\n",
			wantErr: "requests_per_second must be non-negative",
		},
		{
			name:    "negative burst",
			body:    "security:\n  ratelimit:\n    burst: -5\n",
			wantErr: "burst must be non-negative",
		},
		{
			name:    "negative max_concurrent",
			body:    "security:\n  ratelimit:\n    max_concurrent: -2\n",
			wantErr: "max_concurrent must be non-negative",
		},
		{
			name:    "negative max_body_bytes",
			body:    "security:\n  ratelimit:\n    max_body_bytes: -10\n",
			wantErr: "max_body_bytes must be non-negative",
		},
		{
			name:    "negative max_stream_connections",
			body:    "security:\n  ratelimit:\n    max_stream_connections: -3\n",
			wantErr: "max_stream_connections must be non-negative",
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

// TestLoadConfig_ClientAuthDrivesClientAuthType is the IAM-WU-13 honesty proof
// for security.tls.client_auth: the configured string, after a full LoadConfig
// round-trip, resolves to the correct crypto/tls.ClientAuthType both via
// ClientAuthType() AND via BuildServerTLSConfig — the function the server
// listeners actually call. We supply a non-nil CA pool so BuildServerTLSConfig
// does not downgrade require/verify_if_given to NoClientCert (the downgrade
// only fires when clientCAs==nil, which is the no-bundle startup path).
func TestLoadConfig_ClientAuthDrivesClientAuthType(t *testing.T) {
	// A minimal self-signed CA pool so BuildServerTLSConfig sees a non-nil pool
	// and honors the configured ClientAuth without downgrading.
	caPool := x509.NewCertPool()

	cases := []struct {
		clientAuth string
		want       tls.ClientAuthType
	}{
		{"require", tls.RequireAndVerifyClientCert},
		{"verify_if_given", tls.VerifyClientCertIfGiven},
		{"none", tls.NoClientCert},
	}
	for _, tc := range cases {
		t.Run(tc.clientAuth, func(t *testing.T) {
			clearConfigEnv(t)
			path := filepath.Join(t.TempDir(), "config.yaml")
			writeConfig(t, path, `
security:
  tls:
    min_version: "1.3"
    client_auth: `+tc.clientAuth+`
`)
			cfg, err := LoadConfig(path)
			require.NoError(t, err)

			// Layer 1: ClientAuthType() resolver maps the string correctly.
			require.Equal(t, tc.want, cfg.Security.TLS.ClientAuthType(),
				"client_auth %q must resolve via ClientAuthType()", tc.clientAuth)

			// Layer 2: BuildServerTLSConfig (what the listeners call) propagates
			// the same value into tls.Config.ClientAuth when a CA pool is supplied.
			tlsCfg, err := BuildServerTLSConfig(cfg.Security.TLS, caPool)
			require.NoError(t, err)
			require.Equal(t, tc.want, tlsCfg.ClientAuth,
				"client_auth %q must reach tls.Config.ClientAuth via BuildServerTLSConfig", tc.clientAuth)
		})
	}
}

// TestLoadConfig_AuthEnabledMissingFieldsFailValidation pairs with
// TestLoadConfig_AuthEnabledDefaultsSupportedAlgsToFIPSAsymmetricSet (which
// proves enabled=true applies the FIPS supported-algs + claim defaults) and
// TestLoadConfig_AuthDisabledLeavesZeroValue (which proves disabled leaves the
// zero value). Here we assert the third leg of the IAM-WU-13 authentication
// honesty contract: enabled=true with a missing issuer/jwks_url/audience fails
// LoadConfig outright, so an "authenticated" API can never boot unable to
// verify a token. (The individual missing-field messages are covered by
// TestLoadConfig_AuthEnabledRequiresIssuerJWKSAudience; this asserts the
// fail-closed outcome explicitly alongside the defaults/zero-value tests.)
func TestLoadConfig_AuthEnabledMissingFieldsFailValidation(t *testing.T) {
	clearConfigEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeConfig(t, path, `
security:
  authentication:
    enabled: true
`)
	_, err := LoadConfig(path)
	require.Error(t, err, "enabled auth without issuer/jwks_url/audience must fail closed")
}

// TestLoadConfig_RejectsNonMemoryStorageType is the IAM-WU-13 honesty proof for
// storage.type: only "memory" is implemented; any other value (redis, etcd,
// or a typo) must fail LoadConfig so the operator is never misled into
// believing a durable backend is active while the in-memory maps are used.
func TestLoadConfig_RejectsNonMemoryStorageType(t *testing.T) {
	cases := []string{"redis", "etcd", "postgres"}
	for _, backend := range cases {
		t.Run(backend, func(t *testing.T) {
			clearConfigEnv(t)
			path := filepath.Join(t.TempDir(), "config.yaml")
			writeConfig(t, path, "storage:\n  type: "+backend)
			_, err := LoadConfig(path)
			require.Error(t, err)
			require.Contains(t, err.Error(), "storage.type")
		})
	}
}

// TestTLSConfig_ClientAuthRequireWithoutCAPath documents the full contract for
// the client_auth=require + empty ClientCAPath combination (NET-WU-24).
//
// The config layer (LoadConfig / TLSConfig.Validate) accepts this combination
// because enforcement is the responsibility of the flag layer in the binary
// mains (--require-client-cert / --client-ca-path), not the config layer.
// The admission-webhook binary fails CLOSED at startup when requireClientCert
// is true and no CA pool is supplied (cmd/admission-webhook/main.go line ~454).
// The policy-manager uses requireClientCert=false by default for optional mTLS.
//
// What IS machine-verified here is the downstream behavior that must NOT be
// silently ignored: BuildServerTLSConfig DEGRADES to NoClientCert when
// clientCAs==nil, even if client_auth=require is configured. This is the
// documented intentional behavior (CRY-WU-04 comment in tls.go). The test
// makes this explicit so any change to that downgrade path will break this test
// and force a conscious decision.
func TestTLSConfig_ClientAuthRequireWithoutCAPath(t *testing.T) {
	cases := []struct {
		name          string
		clientAuth    string
		caPool        *x509.CertPool // nil = no bundle supplied
		wantAuthInCfg tls.ClientAuthType
		wantAuthInTLS tls.ClientAuthType
		wantLoadErr   bool
	}{
		{
			// (a) require + no CA path: LoadConfig succeeds (flag layer enforces),
			// but BuildServerTLSConfig degrades to NoClientCert — not silently
			// ignored, explicitly documented and tested here (NET-WU-24).
			name:          "require_no_ca_pool_degrades_to_NoClientCert",
			clientAuth:    "require",
			caPool:        nil,
			wantAuthInCfg: tls.RequireAndVerifyClientCert,
			wantAuthInTLS: tls.NoClientCert,
		},
		{
			// (b) require + CA pool: both layers honor RequireAndVerifyClientCert.
			name:          "require_with_ca_pool_enforces_mtls",
			clientAuth:    "require",
			caPool:        x509.NewCertPool(),
			wantAuthInCfg: tls.RequireAndVerifyClientCert,
			wantAuthInTLS: tls.RequireAndVerifyClientCert,
		},
		{
			// (c) none: no client cert in either layer — straightforward.
			name:          "none_no_client_cert",
			clientAuth:    "none",
			caPool:        nil,
			wantAuthInCfg: tls.NoClientCert,
			wantAuthInTLS: tls.NoClientCert,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			clearConfigEnv(t)
			path := filepath.Join(t.TempDir(), "config.yaml")
			writeConfig(t, path, `
security:
  tls:
    min_version: "1.3"
    client_auth: `+tc.clientAuth+`
`)
			cfg, err := LoadConfig(path)
			if tc.wantLoadErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Layer 1: ClientAuthType() resolves the configured string correctly.
			require.Equal(t, tc.wantAuthInCfg, cfg.Security.TLS.ClientAuthType(),
				"ClientAuthType() must resolve client_auth=%q", tc.clientAuth)

			// Layer 2: BuildServerTLSConfig propagates — or intentionally degrades —
			// the ClientAuth value based on whether a CA pool is supplied.
			tlsCfg, err := BuildServerTLSConfig(cfg.Security.TLS, tc.caPool)
			require.NoError(t, err)
			require.Equal(t, tc.wantAuthInTLS, tlsCfg.ClientAuth,
				"BuildServerTLSConfig with caPool=%v must set ClientAuth=%v for client_auth=%q",
				tc.caPool != nil, tc.wantAuthInTLS, tc.clientAuth)
		})
	}
}

func writeConfig(t *testing.T, path string, body string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(strings.TrimSpace(body)+"\n"), 0o600))
}
