package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/viper"
)

// Config represents the application configuration
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Policy   PolicyConfig   `mapstructure:"policy"`
	Audit    AuditConfig    `mapstructure:"audit"`
	Metrics  MetricsConfig  `mapstructure:"metrics"`
	Security SecurityConfig `mapstructure:"security"`
	Storage  StorageConfig  `mapstructure:"storage"`
}

// ServerConfig represents server configuration
type ServerConfig struct {
	Port        int    `mapstructure:"port"`
	MetricsPort int    `mapstructure:"metrics_port"`
	TLSCertPath string `mapstructure:"tls_cert_path"`
	TLSKeyPath  string `mapstructure:"tls_key_path"`
	LogLevel    string `mapstructure:"log_level"`
}

// PolicyConfig represents policy engine configuration
type PolicyConfig struct {
	FailureMode     string `mapstructure:"failure_mode"`     // "fail-open" or "fail-closed"
	DisableDefaults bool   `mapstructure:"disable_defaults"` // skip loading bundled default policies
}

// AuditConfig represents audit logging configuration
type AuditConfig struct {
	Enabled       bool              `mapstructure:"enabled"`
	Backend       string            `mapstructure:"backend"` // "file" or "stdout"
	Config        map[string]string `mapstructure:"config"`
	BufferSize    int               `mapstructure:"buffer_size"`
	FlushInterval string            `mapstructure:"flush_interval"`
	Retention     string            `mapstructure:"retention"`
}

// MetricsConfig represents metrics configuration
type MetricsConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Namespace string `mapstructure:"namespace"`
	Subsystem string `mapstructure:"subsystem"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	TLS            TLSConfig  `mapstructure:"tls"`
	RBAC           RBACConfig `mapstructure:"rbac"`
	Authentication AuthConfig `mapstructure:"authentication"`
	// NOTE: encryption-at-rest is intentionally NOT a field here. The webhook
	// does not encrypt at rest in-process; secret/etcd at-rest protection is a
	// cluster concern provided by a Kubernetes EncryptionConfiguration + KMS
	// (CRY-WU-15). A previously-declared, never-consumed security.encryption
	// stanza was removed to avoid implying an in-app control that did not exist.
	// See deployments/kubernetes/encryption/ and docs/compliance/secrets-at-rest.md.
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	MinVersion   string   `mapstructure:"min_version"`
	CipherSuites []string `mapstructure:"cipher_suites"`
	ClientAuth   string   `mapstructure:"client_auth"`
	// ClientCAPath is the path to a PEM bundle of client-certificate CAs.
	// When set, client_auth=require enforces mutual TLS (RequireAndVerifyClientCert)
	// against this bundle; when empty, client-certificate verification is
	// disabled even if client_auth=require (permissive mode for non-mTLS
	// environments) — see internal/config/tls.go BuildServerTLSConfig (CRY-WU-04).
	ClientCAPath string `mapstructure:"client_ca_path"`
}

// AuthConfig configures OIDC bearer-token authentication for the policy-manager API.
type AuthConfig struct {
	Enabled       bool     `mapstructure:"enabled"`        // when false, API is unauthenticated (dev only; tracked gap)
	Issuer        string   `mapstructure:"issuer"`         // OIDC issuer URL (iss claim must match)
	JWKSURL       string   `mapstructure:"jwks_url"`       // JWKS endpoint (explicit; no discovery round-trip)
	Audience      []string `mapstructure:"audience"`       // accepted aud values (token aud must intersect)
	UsernameClaim string   `mapstructure:"username_claim"` // claim for principal username (default "sub")
	GroupsClaim   string   `mapstructure:"groups_claim"`   // claim for principal groups (default "groups")
	SupportedAlgs []string `mapstructure:"supported_algs"` // FIPS-approved signing algs allow-list
}

// RBACConfig maps authenticated OIDC groups to API roles (viewer/editor/admin).
// There is intentionally no enable flag: RBAC is mounted together with OIDC
// authN (gated by security.authentication.enabled), and DefaultRole already
// expresses an "everyone gets role X" posture. Role-name validation is
// unconditional so a typo can never silently grant or withhold access.
type RBACConfig struct {
	DefaultRole  string        `mapstructure:"default_role"` // role for an authenticated principal with no matching binding ("" => deny mutations)
	RoleBindings []RoleBinding `mapstructure:"role_bindings"`
}

// RoleBinding grants an API role to one or more OIDC groups.
type RoleBinding struct {
	Role   string   `mapstructure:"role"`   // "viewer" | "editor" | "admin"
	Groups []string `mapstructure:"groups"` // OIDC groups granted this role
}

// StorageConfig represents storage configuration
type StorageConfig struct {
	Type   string            `mapstructure:"type"` // "memory", "redis", "etcd"
	Config map[string]string `mapstructure:"config"`
}

// LoadConfig loads configuration from file and environment variables
func LoadConfig(configPath string) (*Config, error) {
	v := viper.New()
	v.SetConfigType("yaml")

	// Set default values
	setDefaults(v)

	// Load from file if provided
	if configPath != "" {
		v.SetConfigFile(configPath)
		if err := v.ReadInConfig(); err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
		}
	}

	// Override with environment variables
	v.SetEnvPrefix("KUBE_POLICIES")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Apply OIDC auth defaults (IAM-WU-13). These depend on
	// security.authentication.enabled, which is only known after unmarshal, so
	// they are set on the struct here rather than via viper.SetDefault.
	applyAuthDefaults(&config.Security.Authentication)

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.port", 8443)
	v.SetDefault("server.metrics_port", 9090)
	v.SetDefault("server.log_level", "info")
	v.SetDefault("server.tls_cert_path", "/etc/certs/tls.crt")
	v.SetDefault("server.tls_key_path", "/etc/certs/tls.key")

	// Policy defaults
	v.SetDefault("policy.failure_mode", "fail-closed")
	v.SetDefault("policy.disable_defaults", false)

	// Audit defaults
	v.SetDefault("audit.enabled", true)
	v.SetDefault("audit.backend", "file")
	v.SetDefault("audit.buffer_size", 1000)
	v.SetDefault("audit.flush_interval", "10s")
	v.SetDefault("audit.retention", "90d")

	// Metrics defaults
	v.SetDefault("metrics.enabled", true)
	v.SetDefault("metrics.namespace", "kube_policies")
	v.SetDefault("metrics.subsystem", "admission")

	// Security defaults
	v.SetDefault("security.tls.min_version", "1.3")
	v.SetDefault("security.tls.client_auth", "require")
	// security.encryption.* defaults removed with the inert EncryptionConfig
	// (CRY-WU-15): at-rest protection is a cluster EncryptionConfiguration + KMS
	// concern, not an in-app control.

	// Storage defaults
	v.SetDefault("storage.type", "memory")
}

// fipsAsymmetricAlgs is the allow-list of asymmetric JWS signing algorithms
// whose verification routes through stdlib crypto/rsa + crypto/ecdsa, i.e. the
// Go FIPS 140-3 module (CRY-WU-14). Symmetric (HMAC) and "none" are excluded so
// an attacker cannot downgrade a token to an unapproved or unsigned algorithm.
var fipsAsymmetricAlgs = []string{
	"RS256", "RS384", "RS512",
	"PS256", "PS384", "PS512",
	"ES256", "ES384", "ES512",
}

// applyAuthDefaults fills the OIDC claim-name and signing-algorithm defaults
// when authentication is enabled and the operator left them unset (IAM-WU-13).
// Disabled auth is left untouched so the zero value stays inert.
func applyAuthDefaults(a *AuthConfig) {
	if !a.Enabled {
		return
	}
	if a.UsernameClaim == "" {
		a.UsernameClaim = "sub"
	}
	if a.GroupsClaim == "" {
		a.GroupsClaim = "groups"
	}
	if len(a.SupportedAlgs) == 0 {
		a.SupportedAlgs = append([]string(nil), fipsAsymmetricAlgs...)
	}
}

// validateConfig validates the configuration
func validateConfig(config *Config) error {
	// Validate server configuration
	if config.Server.Port <= 0 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", config.Server.Port)
	}

	if config.Server.MetricsPort <= 0 || config.Server.MetricsPort > 65535 {
		return fmt.Errorf("invalid metrics port: %d", config.Server.MetricsPort)
	}

	// Validate policy configuration
	if config.Policy.FailureMode != "fail-open" && config.Policy.FailureMode != "fail-closed" {
		return fmt.Errorf("invalid failure mode: %s", config.Policy.FailureMode)
	}

	// Validate audit configuration
	if config.Audit.Enabled {
		validBackends := []string{"file", "stdout"}
		valid := false
		for _, backend := range validBackends {
			if config.Audit.Backend == backend {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid audit backend: %s (supported: file, stdout)", config.Audit.Backend)
		}
		// Audit integrity (AUD-WU-04/05): if integrity_key_path is present it must
		// be non-empty — an empty path means the HMAC chain would be silently
		// disabled, so fail fast rather than ship un-chained "tamper-evident" logs.
		if v, ok := config.Audit.Config["integrity_key_path"]; ok && strings.TrimSpace(v) == "" {
			return fmt.Errorf("audit integrity_key_path is set but empty; provide the mounted HMAC key path or remove the key")
		}
	}

	// Validate the TLS stanza (min_version, cipher_suites, client_auth) so a
	// weak floor or an unknown/non-approved cipher suite fails fast at load
	// rather than at the first handshake (CRY-WU-03).
	if err := config.Security.TLS.Validate(); err != nil {
		return fmt.Errorf("invalid TLS configuration: %w", err)
	}

	// Validate OIDC authentication (IAM-WU-01/13): when enabled, an issuer, a
	// JWKS endpoint, and at least one accepted audience are mandatory. Fail
	// closed at startup rather than booting an "authenticated" API that cannot
	// actually verify a token.
	if config.Security.Authentication.Enabled {
		auth := config.Security.Authentication
		if strings.TrimSpace(auth.Issuer) == "" {
			return fmt.Errorf("security.authentication.issuer is required when authentication is enabled")
		}
		if strings.TrimSpace(auth.JWKSURL) == "" {
			return fmt.Errorf("security.authentication.jwks_url is required when authentication is enabled")
		}
		if len(auth.Audience) == 0 {
			return fmt.Errorf("security.authentication.audience must list at least one accepted audience when authentication is enabled")
		}
	}

	// Validate RBAC role names (IAM-WU-02) unconditionally: every RoleBinding.Role
	// and a set DefaultRole must be one of viewer/editor/admin so a typo cannot
	// silently grant or withhold access. An empty DefaultRole is allowed and
	// means "deny mutations for principals with no matching binding". There is no
	// enable flag to gate this on — RBAC enforcement is mounted with OIDC authN.
	for i, rb := range config.Security.RBAC.RoleBindings {
		if !validRole(rb.Role) {
			return fmt.Errorf("security.rbac.role_bindings[%d].role %q is invalid (must be viewer, editor, or admin)", i, rb.Role)
		}
	}
	if dr := strings.TrimSpace(config.Security.RBAC.DefaultRole); dr != "" && !validRole(dr) {
		return fmt.Errorf("security.rbac.default_role %q is invalid (must be viewer, editor, or admin)", config.Security.RBAC.DefaultRole)
	}

	return nil
}

// validRole reports whether name is one of the three API roles.
func validRole(name string) bool {
	switch name {
	case "viewer", "editor", "admin":
		return true
	default:
		return false
	}
}
