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
	TLS            TLSConfig        `mapstructure:"tls"`
	RBAC           RBACConfig       `mapstructure:"rbac"`
	Encryption     EncryptionConfig `mapstructure:"encryption"`
	Authentication AuthConfig       `mapstructure:"authentication"`
}

// TLSConfig represents TLS configuration
type TLSConfig struct {
	MinVersion   string   `mapstructure:"min_version"`
	CipherSuites []string `mapstructure:"cipher_suites"`
	ClientAuth   string   `mapstructure:"client_auth"`
}

// RBACConfig represents RBAC configuration
type RBACConfig struct {
	Enabled     bool              `mapstructure:"enabled"`
	Provider    string            `mapstructure:"provider"`
	Config      map[string]string `mapstructure:"config"`
	DefaultRole string            `mapstructure:"default_role"`
}

// EncryptionConfig represents encryption configuration
type EncryptionConfig struct {
	AtRest    EncryptionAtRestConfig    `mapstructure:"at_rest"`
	InTransit EncryptionInTransitConfig `mapstructure:"in_transit"`
}

// EncryptionAtRestConfig represents encryption at rest configuration
type EncryptionAtRestConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Algorithm string `mapstructure:"algorithm"`
	KeySource string `mapstructure:"key_source"`
}

// EncryptionInTransitConfig represents encryption in transit configuration
type EncryptionInTransitConfig struct {
	Enabled bool   `mapstructure:"enabled"`
	Mode    string `mapstructure:"mode"` // "strict", "permissive"
}

// AuthConfig represents authentication configuration
type AuthConfig struct {
	Providers []AuthProvider `mapstructure:"providers"`
}

// AuthProvider represents an authentication provider
type AuthProvider struct {
	Name   string            `mapstructure:"name"`
	Type   string            `mapstructure:"type"` // "oidc", "ldap", "cert"
	Config map[string]string `mapstructure:"config"`
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
	v.SetDefault("security.rbac.enabled", true)
	v.SetDefault("security.encryption.at_rest.enabled", true)
	v.SetDefault("security.encryption.at_rest.algorithm", "AES-256-GCM")
	v.SetDefault("security.encryption.in_transit.enabled", true)
	v.SetDefault("security.encryption.in_transit.mode", "strict")

	// Storage defaults
	v.SetDefault("storage.type", "memory")
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
	}

	if config.Security.TLS.MinVersion != "1.3" {
		return fmt.Errorf("invalid TLS min version: %s (supported: 1.3)", config.Security.TLS.MinVersion)
	}

	return nil
}
