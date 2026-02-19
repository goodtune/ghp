// Package config handles server configuration from YAML files and environment variables.
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/knadh/koanf/parsers/yaml"
	"github.com/knadh/koanf/providers/env"
	"github.com/knadh/koanf/providers/file"
	"github.com/knadh/koanf/v2"
)

// Config represents the complete server configuration.
type Config struct {
	GitHub   GitHubConfig   `koanf:"github"`
	Vault    VaultConfig    `koanf:"vault"`
	Database DatabaseConfig `koanf:"database"`
	Server   ServerConfig   `koanf:"server"`
	TLS      TLSConfig      `koanf:"tls"`
	Tokens   TokensConfig   `koanf:"tokens"`
	Logging  LoggingConfig  `koanf:"logging"`
	Metrics  MetricsConfig  `koanf:"metrics"`
	OTEL     OTELConfig     `koanf:"otel"`
	Admins   []string       `koanf:"admins"`

	EncryptionKey string `koanf:"encryption_key"`

	// DevMode enables test-only endpoints (e.g. /auth/test-login).
	// Must never be enabled in production.
	DevMode bool `koanf:"dev_mode"`
}

// VaultConfig holds optional HashiCorp Vault integration settings.
// When Enabled is true, Vault becomes the source of truth for the
// encryption key and GitHub App credentials (multi-app mode).
type VaultConfig struct {
	Enabled  bool   `koanf:"enabled"`
	Addr     string `koanf:"addr"`      // e.g. "https://vault.example.com:8200"
	RoleID   string `koanf:"role_id"`   // AppRole role ID
	SecretID string `koanf:"secret_id"` // AppRole secret ID
	Mount    string `koanf:"mount"`     // KV v2 mount path (default: "secret")
	Prefix   string `koanf:"prefix"`    // Key prefix under mount (default: "ghp")
}

type TLSConfig struct {
	Certificates []CertificateConfig `koanf:"certificates"`
}

type CertificateConfig struct {
	CertFile string `koanf:"cert_file"`
	KeyFile  string `koanf:"key_file"`
}

type GitHubConfig struct {
	AppID          int64  `koanf:"app_id"`
	ClientID       string `koanf:"client_id"`
	ClientSecret   string `koanf:"client_secret"`
	PrivateKeyFile string `koanf:"private_key_file"`
	EnterpriseSlug string `koanf:"enterprise_slug"`
}

type DatabaseConfig struct {
	Driver string `koanf:"driver"`
	DSN    string `koanf:"dsn"`
}

type ServerConfig struct {
	Listen                  string `koanf:"listen"`
	HTTPSListen             string `koanf:"https_listen"`
	HTTPListen              string `koanf:"http_listen"`
	ManagementHost          string `koanf:"management_host"`
	SystemdSocketActivation bool   `koanf:"systemd_socket_activation"`
	BaseURL                 string `koanf:"base_url"`
}

type TokensConfig struct {
	DefaultDuration time.Duration `koanf:"default_duration"`
	MaxDuration     time.Duration `koanf:"max_duration"`
}

type LoggingConfig struct {
	Output string         `koanf:"output"`
	Level  string         `koanf:"level"`
	File   LogFileConfig  `koanf:"file"`
}

type LogFileConfig struct {
	Path string `koanf:"path"`
}

type MetricsConfig struct {
	Enabled bool `koanf:"enabled"`
}

type OTELConfig struct {
	Enabled  bool   `koanf:"enabled"`
	Endpoint string `koanf:"endpoint"`
	Protocol string `koanf:"protocol"`
}

// Defaults returns a Config with sensible defaults.
func Defaults() *Config {
	return &Config{
		Database: DatabaseConfig{
			Driver: "sqlite",
			DSN:    "ghp.db",
		},
		Server: ServerConfig{
			Listen: ":8080",
		},
		Tokens: TokensConfig{
			DefaultDuration: 24 * time.Hour,
			MaxDuration:     7 * 24 * time.Hour,
		},
		Logging: LoggingConfig{
			Output: "stdout",
			Level:  "info",
		},
		Metrics: MetricsConfig{
			Enabled: false,
		},
		OTEL: OTELConfig{
			Protocol: "grpc",
		},
	}
}

// Load reads configuration from a YAML file and applies environment variable overrides.
func Load(path string) (*Config, error) {
	k := koanf.New(".")

	cfg := Defaults()

	if path != "" {
		if err := k.Load(file.Provider(path), yaml.Parser()); err != nil {
			return nil, fmt.Errorf("loading config file %s: %w", path, err)
		}
	}

	// Environment variable overrides: GHP_GITHUB_CLIENT_ID -> github.client_id
	// Only the first underscore separates the section from the field name;
	// subsequent underscores are preserved as literal characters in field names
	// (e.g. GHP_GITHUB_CLIENT_ID -> github.client_id, GHP_DEV_MODE -> dev_mode).
	if err := k.Load(env.Provider("GHP_", ".", func(s string) string {
		s = strings.TrimPrefix(s, "GHP_")
		s = strings.ToLower(s)
		if i := strings.Index(s, "_"); i > 0 {
			section, field := s[:i], s[i+1:]
			switch section {
			case "github", "vault", "database", "server", "tls", "tokens", "logging", "metrics", "otel":
				// Handle 3-level nesting for logging.file.*
				if section == "logging" && strings.HasPrefix(field, "file_") {
					return "logging.file." + field[len("file_"):]
				}
				return section + "." + field
			}
		}
		return s
	}), nil); err != nil {
		return nil, fmt.Errorf("loading env vars: %w", err)
	}

	if err := k.Unmarshal("", cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	return cfg, nil
}

// VaultEnabled returns true if Vault integration is configured.
func (c *Config) VaultEnabled() bool {
	return c.Vault.Enabled
}

// Validate checks the configuration for consistency errors.
func (c *Config) Validate() error {
	if c.Vault.Enabled {
		if c.Vault.Addr == "" {
			return fmt.Errorf("vault.addr is required when vault is enabled")
		}
		if c.Vault.RoleID == "" {
			return fmt.Errorf("vault.role_id is required when vault is enabled")
		}
		if c.Vault.SecretID == "" {
			return fmt.Errorf("vault.secret_id is required when vault is enabled")
		}
		if c.EncryptionKey != "" {
			return fmt.Errorf("encryption_key must not be set locally when vault is enabled (it will be read from vault)")
		}
		if c.GitHub.ClientID != "" || c.GitHub.ClientSecret != "" {
			return fmt.Errorf("github.client_id and github.client_secret must not be set locally when vault is enabled (app credentials come from vault)")
		}
	}
	return nil
}

// IsAdmin returns true if the given GitHub username is in the admin list.
func (c *Config) IsAdmin(username string) bool {
	for _, admin := range c.Admins {
		if strings.EqualFold(admin, username) {
			return true
		}
	}
	return false
}
