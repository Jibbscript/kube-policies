package config

import (
	"fmt"
	"os"

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
	BundleURL       string            `mapstructure:"bundle_url"`
	RefreshInterval string            `mapstructure:"refresh_interval"`
	CacheSize       int               `mapstructure:"cache_size"`
	Timeout         string            `mapstructure:"timeout"`
	FailureMode     string            `mapstructure:"failure_mode"` // "fail-open" or "fail-closed"
	DefaultPolicies []string          `mapstructure:"default_policies"`
	Frameworks      map[string]string `mapstructure:"frameworks"`
}

// AuditConfig represents audit logging configuration
type AuditConfig struct {
	Enabled     bool              `mapstructure:"enabled"`
	Backend     string            `mapstructure:"backend"` // "file", "elasticsearch", "webhook"
	Config      map[string]string `mapstructure:"config"`
	BufferSize  int               `mapstructure:"buffer_size"`
	FlushInterval string          `mapstructure:"flush_interval"`
	Retention   string            `mapstructure:"retention"`
}

// MetricsConfig represents metrics configuration
type MetricsConfig struct {
	Enabled   bool   `mapstructure:"enabled"`
	Namespace string `mapstructure:"namespace"`
	Subsystem string `mapstructure:"subsystem"`
}

// SecurityConfig represents security configuration
type SecurityConfig struct {
	TLS         TLSConfig         `mapstructure:"tls"`
	RBAC        RBACConfig        `mapstructure:"rbac"`
	Encryption  EncryptionConfig  `mapstructure:"encryption"`
	Authentication AuthConfig     `mapstructure:"authentication"`
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
	viper.SetConfigType("yaml")
	
	// Set default values
	setDefaults()

	// Load from file if provided
	if configPath != "" {
		viper.SetConfigFile(configPath)
		if err := viper.ReadInConfig(); err != nil {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("failed to read config file: %w", err)
			}
		}
	}

	// Override with environment variables
	viper.AutomaticEnv()
	viper.SetEnvPrefix("KUBE_POLICIES")

	var config Config
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults() {
	// Server defaults
	viper.SetDefault("server.port", 8443)
	viper.SetDefault("server.metrics_port", 9090)
	viper.SetDefault("server.log_level", "info")
	viper.SetDefault("server.tls_cert_path", "/etc/certs/tls.crt")
	viper.SetDefault("server.tls_key_path", "/etc/certs/tls.key")

	// Policy defaults
	viper.SetDefault("policy.refresh_interval", "30s")
	viper.SetDefault("policy.cache_size", 1000)
	viper.SetDefault("policy.timeout", "5s")
	viper.SetDefault("policy.failure_mode", "fail-closed")

	// Audit defaults
	viper.SetDefault("audit.enabled", true)
	viper.SetDefault("audit.backend", "file")
	viper.SetDefault("audit.buffer_size", 1000)
	viper.SetDefault("audit.flush_interval", "10s")
	viper.SetDefault("audit.retention", "90d")

	// Metrics defaults
	viper.SetDefault("metrics.enabled", true)
	viper.SetDefault("metrics.namespace", "kube_policies")
	viper.SetDefault("metrics.subsystem", "admission")

	// Security defaults
	viper.SetDefault("security.tls.min_version", "1.3")
	viper.SetDefault("security.tls.client_auth", "require")
	viper.SetDefault("security.rbac.enabled", true)
	viper.SetDefault("security.encryption.at_rest.enabled", true)
	viper.SetDefault("security.encryption.at_rest.algorithm", "AES-256-GCM")
	viper.SetDefault("security.encryption.in_transit.enabled", true)
	viper.SetDefault("security.encryption.in_transit.mode", "strict")

	// Storage defaults
	viper.SetDefault("storage.type", "memory")
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
		validBackends := []string{"file", "elasticsearch", "webhook", "stdout"}
		valid := false
		for _, backend := range validBackends {
			if config.Audit.Backend == backend {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid audit backend: %s", config.Audit.Backend)
		}
	}

	// Validate TLS configuration
	validTLSVersions := []string{"1.2", "1.3"}
	valid := false
	for _, version := range validTLSVersions {
		if config.Security.TLS.MinVersion == version {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid TLS min version: %s", config.Security.TLS.MinVersion)
	}

	return nil
}

// GetDefaultConfig returns a default configuration
func GetDefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port:        8443,
			MetricsPort: 9090,
			LogLevel:    "info",
			TLSCertPath: "/etc/certs/tls.crt",
			TLSKeyPath:  "/etc/certs/tls.key",
		},
		Policy: PolicyConfig{
			RefreshInterval: "30s",
			CacheSize:       1000,
			Timeout:         "5s",
			FailureMode:     "fail-closed",
		},
		Audit: AuditConfig{
			Enabled:       true,
			Backend:       "file",
			BufferSize:    1000,
			FlushInterval: "10s",
			Retention:     "90d",
		},
		Metrics: MetricsConfig{
			Enabled:   true,
			Namespace: "kube_policies",
			Subsystem: "admission",
		},
		Security: SecurityConfig{
			TLS: TLSConfig{
				MinVersion: "1.3",
				ClientAuth: "require",
			},
			RBAC: RBACConfig{
				Enabled: true,
			},
			Encryption: EncryptionConfig{
				AtRest: EncryptionAtRestConfig{
					Enabled:   true,
					Algorithm: "AES-256-GCM",
				},
				InTransit: EncryptionInTransitConfig{
					Enabled: true,
					Mode:    "strict",
				},
			},
		},
		Storage: StorageConfig{
			Type: "memory",
		},
	}
}

