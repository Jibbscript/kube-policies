package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// ParseRetention parses an audit-retention duration. It accepts any value
// time.ParseDuration understands (e.g. "2160h") plus a 'd' (days) suffix
// (e.g. "90d") that the stdlib parser rejects. Days are exactly 24h. This is
// the single source of truth for retention parsing across config validation
// and the audit file backend (AUD-WU-07, AU-11).
func ParseRetention(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty retention")
	}
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid days value %q: %w", s, err)
		}
		if days < 0 {
			return 0, fmt.Errorf("negative retention %q", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

// validateAudit validates the audit stanza (AUD-WU-06/07/09/14). Split out from
// validateConfig so it can be unit-tested without a fully-populated Config.
func validateAudit(a *AuditConfig) error {
	if !a.Enabled {
		return nil
	}
	validBackends := []string{"file", "stdout", "forward"}
	valid := false
	for _, backend := range validBackends {
		if a.Backend == backend {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid audit backend: %s (supported: file, stdout, forward)", a.Backend)
	}
	// Audit integrity (AUD-WU-04/05): if integrity_key_path is present it must be
	// non-empty — an empty path means the HMAC chain would be silently disabled,
	// so fail fast rather than ship un-chained "tamper-evident" logs.
	if v, ok := a.Config["integrity_key_path"]; ok && strings.TrimSpace(v) == "" {
		return fmt.Errorf("audit integrity_key_path is set but empty; provide the mounted HMAC key path or remove the key")
	}
	// AUD-WU-09: the forwarding backend must have a destination, else it would
	// silently drop every record — the exact failure mode that got the original
	// webhook/elasticsearch stubs removed.
	if a.Backend == "forward" && strings.TrimSpace(a.Config["forward_address"]) == "" {
		return fmt.Errorf("audit backend 'forward' requires config.forward_address (host:port of the SIEM/syslog-TLS receiver)")
	}
	// AUD-WU-07 (AU-11): enforce the FedRAMP-Moderate 90-day online-retention
	// floor. Parsing supports a 'd' suffix that time.ParseDuration does not.
	if strings.TrimSpace(a.Retention) != "" {
		d, err := ParseRetention(a.Retention)
		if err != nil {
			return fmt.Errorf("invalid audit.retention %q: %w", a.Retention, err)
		}
		if d < 90*24*time.Hour {
			return fmt.Errorf("audit.retention %q is below the FedRAMP-Moderate minimum of 90d (AU-11)", a.Retention)
		}
	}
	// AUD-WU-14: only drop|block are meaningful overflow policies.
	switch a.OverflowPolicy {
	case "", "drop", "block":
	default:
		return fmt.Errorf("invalid audit.overflow_policy %q (supported: drop, block)", a.OverflowPolicy)
	}
	// AUD-WU-06 (AU-4 capacity): negative rotation bounds are invalid.
	if a.MaxSizeMB < 0 {
		return fmt.Errorf("audit.max_size_mb must be >= 0, got %d", a.MaxSizeMB)
	}
	if a.MaxBackups < 0 {
		return fmt.Errorf("audit.max_backups must be >= 0, got %d", a.MaxBackups)
	}
	return nil
}

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
	// Profiles selects which bundled enforcement profile(s) to activate
	// (POL-WU-23), e.g. ["pss-restricted"] or ["cis"]. When non-empty, the
	// engine enables EXACTLY the union of the selected profiles' policies and
	// disables the rest. When empty, the engine keeps its default-enabled set
	// (security-baseline) so existing deployments are unchanged. Known names are
	// in policy.EnforcementProfiles.
	Profiles []string `mapstructure:"profiles"`
}

// AuditConfig represents audit logging configuration
type AuditConfig struct {
	Enabled       bool              `mapstructure:"enabled"`
	Backend       string            `mapstructure:"backend"` // "file", "stdout", or "forward"
	Config        map[string]string `mapstructure:"config"`
	BufferSize    int               `mapstructure:"buffer_size"`
	FlushInterval string            `mapstructure:"flush_interval"`
	// Retention is the minimum online-retention window for audit records
	// (AU-11). Accepts Go durations plus a 'd' (days) suffix, e.g. "90d".
	// FedRAMP-Moderate requires >= 90 days; validateConfig rejects shorter.
	Retention string `mapstructure:"retention"`
	// MaxSizeMB caps a single audit file before rotation (AU-4 capacity).
	MaxSizeMB int `mapstructure:"max_size_mb"`
	// MaxBackups bounds the number of rotated files kept on disk. 0 keeps all
	// (retention/age governs deletion instead).
	MaxBackups int `mapstructure:"max_backups"`
	// OverflowPolicy controls behavior when the in-memory buffer is full:
	// "drop" (default, never blocks the hot path) or "block" (fail-closed —
	// apply backpressure so no audit record is silently lost, AU-5/AU-9).
	OverflowPolicy string `mapstructure:"overflow_policy"`
	// RedactObjects redacts Secret/PII payloads (Object/OldObject) before they
	// are persisted to the durable backend (AU-3(1)/SI-12). Default true.
	RedactObjects bool `mapstructure:"redact_objects"`
}

// MetricsConfig represents metrics configuration
type MetricsConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Namespace string `mapstructure:"namespace"`
	Subsystem string `mapstructure:"subsystem"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	TLS            TLSConfig       `mapstructure:"tls"`
	RBAC           RBACConfig      `mapstructure:"rbac"`
	Authentication AuthConfig      `mapstructure:"authentication"`
	RateLimit      RateLimitConfig `mapstructure:"ratelimit"`
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

// RateLimitConfig configures the shared HTTP rate-limiting / DoS-protection
// middleware (NET-WU-14/15, RES-WU-17) applied to the webhook, policy-manager,
// and dashboard gin routers. All limits are PER-PROCESS (per replica), not
// cluster-wide: each pod constructs its own limiter, so the effective
// cluster-wide ceiling is roughly limit * replicaCount.
//
// Defaults are tuned to protect the fail-closed admission webhook — which is on
// the cluster's critical write path — from a request flood WITHOUT throttling
// legitimate apiserver admission traffic. The apiserver serializes admission
// calls per webhook with a 10s timeout and modest in-flight concurrency, so a
// 50 req/s steady rate with a burst of 100 absorbs normal spikes (rollouts,
// CRD churn) while still rejecting a runaway client. See
// internal/middleware/ratelimit.go for the enforcement details.
type RateLimitConfig struct {
	// Enabled toggles the whole middleware. When false the limiter, the
	// concurrency cap, and the body cap are all no-ops (pass-through). Default
	// true.
	Enabled bool `mapstructure:"enabled"`

	// RequestsPerSecond is the sustained token-bucket refill rate (req/s) for
	// the global request limiter. <= 0 disables the rate limiter while leaving
	// the other protections active. Default 50.
	RequestsPerSecond float64 `mapstructure:"requests_per_second"`

	// Burst is the token-bucket depth — the maximum number of requests admitted
	// in an instantaneous spike before the per-second rate applies. <= 0
	// disables the rate limiter. Default 100.
	Burst int `mapstructure:"burst"`

	// MaxConcurrent caps the number of in-flight requests handled
	// simultaneously. Excess requests are rejected with 429 (non-blocking
	// acquire) rather than queued, so a slow upstream cannot accumulate an
	// unbounded backlog. <= 0 disables the concurrency cap. Default 100.
	MaxConcurrent int `mapstructure:"max_concurrent"`

	// MaxBodyBytes caps the request body size; oversized requests get 413. The
	// admission AdmissionReview for a large object can exceed 1MiB, so the
	// default 3MiB (3145728) leaves headroom for legitimate workloads while
	// still rejecting absurd payloads. <= 0 disables the body cap.
	MaxBodyBytes int64 `mapstructure:"max_body_bytes"`

	// MaxStreamConnections caps concurrent long-lived SSE connections on the
	// decisions stream endpoint, separately from MaxConcurrent (SSE connections
	// are held open and would otherwise exhaust the general concurrency budget).
	// The N+1th concurrent stream gets 429; the slot is released on disconnect.
	// <= 0 disables the stream cap. Default 100.
	MaxStreamConnections int `mapstructure:"max_stream_connections"`
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
	v.SetDefault("audit.max_size_mb", 100)
	v.SetDefault("audit.max_backups", 0) // 0 = keep all; retention/age governs deletion
	v.SetDefault("audit.overflow_policy", "drop")
	v.SetDefault("audit.redact_objects", true)

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

	// Rate-limiting / DoS-protection defaults (NET-WU-14/15, RES-WU-17). Enabled
	// by default with limits tuned to protect the fail-closed webhook from a
	// flood without throttling legitimate apiserver admission traffic. See
	// RateLimitConfig for the per-replica rationale of each value.
	v.SetDefault("security.ratelimit.enabled", true)
	v.SetDefault("security.ratelimit.requests_per_second", 50.0)
	v.SetDefault("security.ratelimit.burst", 100)
	v.SetDefault("security.ratelimit.max_concurrent", 100)
	v.SetDefault("security.ratelimit.max_body_bytes", 3145728) // 3 MiB
	v.SetDefault("security.ratelimit.max_stream_connections", 100)

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

	// Validate audit configuration (AUD-WU-06/07/09/14).
	if err := validateAudit(&config.Audit); err != nil {
		return err
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

	// Validate rate-limiting / DoS-protection bounds (NET-WU-14/15, RES-WU-17):
	// every limit must be non-negative. A negative value is an operator typo that
	// would otherwise be silently treated as "disabled" by the middleware; fail
	// fast so the misconfiguration is caught at load. Zero is allowed and means
	// "disable that particular protection" (documented on each field).
	rl := config.Security.RateLimit
	if rl.RequestsPerSecond < 0 {
		return fmt.Errorf("security.ratelimit.requests_per_second must be non-negative, got %g", rl.RequestsPerSecond)
	}
	if rl.Burst < 0 {
		return fmt.Errorf("security.ratelimit.burst must be non-negative, got %d", rl.Burst)
	}
	if rl.MaxConcurrent < 0 {
		return fmt.Errorf("security.ratelimit.max_concurrent must be non-negative, got %d", rl.MaxConcurrent)
	}
	if rl.MaxBodyBytes < 0 {
		return fmt.Errorf("security.ratelimit.max_body_bytes must be non-negative, got %d", rl.MaxBodyBytes)
	}
	if rl.MaxStreamConnections < 0 {
		return fmt.Errorf("security.ratelimit.max_stream_connections must be non-negative, got %d", rl.MaxStreamConnections)
	}

	// Validate storage type (IAM-WU-13 honesty). Only "memory" is implemented;
	// redis and etcd are future intent only. Accepting an unknown value here
	// would silently ignore it while the in-memory store continues to be used,
	// misleading the operator into believing a durable backend is active.
	if t := strings.TrimSpace(config.Storage.Type); t != "memory" {
		return fmt.Errorf("storage.type %q is not implemented (only \"memory\" is supported)", t)
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
