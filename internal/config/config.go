// Package config handles server configuration from YAML files and environment variables.
package config

import (
	"fmt"
	"os"
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
	// MinVersion sets the minimum TLS version accepted by the server.
	// Allowed values: "1.2" (default), "1.3".
	MinVersion string `koanf:"min_version"`
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
	BaseURL        string `koanf:"base_url"`          // GitHub API base URL for GHES (default: https://api.github.com)
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
	// JWTPrivateKey is the PEM-encoded RSA private key used to sign broker JWTs
	// with RS256 (asymmetric signing). When set, it takes precedence over
	// JWTPrivateKeyFile and the broker endpoints are enabled. Downstream services
	// can verify tokens using the corresponding public key (via /.well-known/jwks.json)
	// without being able to forge them.
	JWTPrivateKey string `koanf:"jwt_private_key"`
	// JWTPrivateKeyFile is the path to a PEM-encoded RSA private key file.
	// Used when JWTPrivateKey is not set directly.
	JWTPrivateKeyFile string `koanf:"jwt_private_key_file"`
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

	// Comma-separated list env vars for slice fields. koanf unmarshals
	// a single env var string into a one-element slice, so we split on
	// commas to support e.g. GHP_ADMINS="alice,bob".
	cfg.Admins = splitCommaSlice(cfg.Admins)
	cfg.Auth.AllowedRedirects = splitCommaSlice(cfg.Auth.AllowedRedirects)

	// Convenience env vars for the common single-certificate case.
	// GHP_TLS_CERT_FILE / GHP_TLS_KEY_FILE populate Certificates[0]
	// when the slice is empty (the koanf env mapper cannot address
	// array elements).
	if len(cfg.TLS.Certificates) == 0 {
		certFile := os.Getenv("GHP_TLS_CERT_FILE")
		keyFile := os.Getenv("GHP_TLS_KEY_FILE")
		if certFile != "" && keyFile != "" {
			cfg.TLS.Certificates = []CertificateConfig{
				{CertFile: certFile, KeyFile: keyFile},
			}
		}
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

// splitCommaSlice re-splits a string slice so that any element containing
// commas is expanded. This lets env vars like GHP_ADMINS="a,b" work even
// though koanf treats the value as a single string.
func splitCommaSlice(ss []string) []string {
	var out []string
	for _, s := range ss {
		for _, part := range strings.Split(s, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
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
