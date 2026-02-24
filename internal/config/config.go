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
	Database DatabaseConfig `koanf:"database"`
	Server   ServerConfig   `koanf:"server"`
	TLS      TLSConfig      `koanf:"tls"`
	Tokens   TokensConfig   `koanf:"tokens"`
	Logging  LoggingConfig  `koanf:"logging"`
	Metrics  MetricsConfig  `koanf:"metrics"`
	OTEL     OTELConfig     `koanf:"otel"`
	Admins   []string       `koanf:"admins"`
	Auth     AuthConfig     `koanf:"auth"`

	EncryptionKey string `koanf:"encryption_key"`

	// DevMode enables test-only endpoints (e.g. /auth/test-login).
	// Must never be enabled in production.
	DevMode bool `koanf:"dev_mode"`
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
	PrivateKey     string `koanf:"private_key"`      // PEM contents directly (GHP_GITHUB_PRIVATE_KEY)
	PrivateKeyFile string `koanf:"private_key_file"`  // Path to PEM file (GHP_GITHUB_PRIVATE_KEY_FILE)
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
	Output string        `koanf:"output"`
	Level  string        `koanf:"level"`
	File   LogFileConfig `koanf:"file"`
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

// AuthConfig holds settings for the OAuth broker feature.
type AuthConfig struct {
	// JWTSecret is the shared HMAC-SHA256 secret used to sign broker JWTs.
	// When set, the /auth/authorize and /auth/callback broker endpoints are enabled.
	JWTSecret string `koanf:"jwt_secret"`
	// AllowedRedirects is a list of permitted redirect_uri values or wildcard
	// domain patterns (e.g. "*.example.com") for the OAuth broker flow.
	AllowedRedirects []string `koanf:"allowed_redirects"`
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
			case "github", "database", "server", "tls", "tokens", "logging", "metrics", "otel", "auth":
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

// ReloadFrom re-reads a YAML config file and updates hot-reloadable fields
// in-place. Fields that require a restart (database, server listen addresses,
// TLS certificates) are not updated.
func (c *Config) ReloadFrom(path string) error {
	fresh, err := Load(path)
	if err != nil {
		return err
	}
	c.Admins = fresh.Admins
	c.Tokens = fresh.Tokens
	c.Logging = fresh.Logging
	c.Metrics = fresh.Metrics
	c.Auth = fresh.Auth
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
