// Package vault provides HashiCorp Vault integration for ghp.
//
// When enabled, Vault serves as the source of truth for:
//   - GitHub App credentials (client_id, client_secret, private_key)
//   - The encryption key used for token-at-rest encryption
//   - Multi-app configuration (one secret per GitHub App)
//
// Authentication uses the AppRole method. All secrets are stored in
// a KV version 2 secrets engine.
//
// Expected Vault layout (under the configured mount and prefix):
//
//	{mount}/data/{prefix}/config          → {"encryption_key": "hex..."}
//	{mount}/data/{prefix}/apps/{slug}     → {"client_id": "...", "client_secret": "...", "app_id": 123, ...}
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// validSlug matches slugs that start with an alphanumeric character
// followed by alphanumerics, dots, underscores, or hyphens.
var validSlug = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// validateSlug checks that a slug is safe for use in Vault paths.
func validateSlug(slug string) error {
	if slug == "" {
		return fmt.Errorf("slug must not be empty")
	}
	if strings.Contains(slug, "..") {
		return fmt.Errorf("slug must not contain '..'")
	}
	if !validSlug.MatchString(slug) {
		return fmt.Errorf("invalid slug %q: must match %s", slug, validSlug.String())
	}
	return nil
}

// AppSecret holds the credentials for a single GitHub App stored in Vault.
type AppSecret struct {
	Slug           string `json:"slug"`
	AppID          int64  `json:"app_id"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	PrivateKey     string `json:"private_key,omitempty"`
	EnterpriseSlug string `json:"enterprise_slug,omitempty"`
	DisplayName    string `json:"display_name,omitempty"`
}

// Client talks to HashiCorp Vault using its HTTP API.
type Client struct {
	addr       string
	token      string // current Vault token (from AppRole login)
	httpClient *http.Client
	logger     *slog.Logger

	mount  string // KV v2 mount path (e.g. "secret")
	prefix string // key prefix (e.g. "ghp")

	// AppRole credentials for token renewal.
	roleID   string
	secretID string

	mu       sync.RWMutex
	tokenTTL time.Time
}

// Config holds the configuration needed to connect to Vault.
type Config struct {
	Addr     string `koanf:"addr"`      // e.g. "https://vault.example.com:8200"
	RoleID   string `koanf:"role_id"`   // AppRole role ID
	SecretID string `koanf:"secret_id"` // AppRole secret ID
	Mount    string `koanf:"mount"`     // KV v2 mount (default: "secret")
	Prefix   string `koanf:"prefix"`    // Key prefix (default: "ghp")
}

// NewClient creates a Vault client and authenticates via AppRole.
func NewClient(cfg Config, logger *slog.Logger) (*Client, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("vault address is required")
	}
	if cfg.RoleID == "" {
		return nil, fmt.Errorf("vault role_id is required")
	}
	if cfg.SecretID == "" {
		return nil, fmt.Errorf("vault secret_id is required")
	}
	if cfg.Mount == "" {
		cfg.Mount = "secret"
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "ghp"
	}

	c := &Client{
		addr:     strings.TrimRight(cfg.Addr, "/"),
		mount:    cfg.Mount,
		prefix:   cfg.Prefix,
		roleID:   cfg.RoleID,
		secretID: cfg.SecretID,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		logger: logger,
	}

	if err := c.login(context.Background()); err != nil {
		return nil, fmt.Errorf("vault AppRole login: %w", err)
	}

	return c, nil
}

// loginLocked authenticates to Vault using the AppRole method and stores the token.
// The caller must hold c.mu (write lock).
func (c *Client) loginLocked(ctx context.Context) error {
	payload := struct {
		RoleID   string `json:"role_id"`
		SecretID string `json:"secret_id"`
	}{
		RoleID:   c.roleID,
		SecretID: c.secretID,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling login body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.addr+"/v1/auth/approle/login", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("connecting to vault: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading vault response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("vault returned %d: %s", resp.StatusCode, respBody)
	}

	var result struct {
		Auth struct {
			ClientToken   string `json:"client_token"`
			LeaseDuration int    `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return fmt.Errorf("parsing vault auth response: %w", err)
	}

	if result.Auth.ClientToken == "" {
		return fmt.Errorf("vault returned empty client_token")
	}
	if result.Auth.LeaseDuration <= 0 {
		return fmt.Errorf("vault returned invalid lease_duration: %d", result.Auth.LeaseDuration)
	}

	c.token = result.Auth.ClientToken
	c.tokenTTL = time.Now().Add(time.Duration(result.Auth.LeaseDuration) * time.Second)

	c.logger.Info("vault_authenticated", "ttl_seconds", result.Auth.LeaseDuration)
	return nil
}

// login acquires a write lock and authenticates to Vault.
func (c *Client) login(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.loginLocked(ctx)
}

// ensureToken re-authenticates if the current token is close to expiry.
func (c *Client) ensureToken(ctx context.Context) error {
	c.mu.RLock()
	valid := time.Until(c.tokenTTL) > 30*time.Second
	c.mu.RUnlock()

	if valid {
		return nil
	}

	// Acquire write lock and double-check TTL to avoid thundering herd.
	c.mu.Lock()
	defer c.mu.Unlock()

	if time.Until(c.tokenTTL) > 30*time.Second {
		return nil
	}

	c.logger.Info("vault_token_renewing", "msg", "vault token near expiry, re-authenticating")
	return c.loginLocked(ctx)
}

// readKV2 reads a secret from the KV v2 engine at the given path.
func (c *Client) readKV2(ctx context.Context, path string) (map[string]interface{}, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/v1/%s/data/%s/%s", c.addr, c.mount, c.prefix, path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	c.mu.RLock()
	req.Header.Set("X-Vault-Token", c.token)
	c.mu.RUnlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault read %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading vault response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("vault secret not found: %s/%s", c.prefix, path)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault returned %d for %s: %s", resp.StatusCode, path, body)
	}

	var result struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing vault response for %s: %w", path, err)
	}

	if result.Data.Data == nil {
		return nil, fmt.Errorf("vault secret at %s/%s has no data", c.prefix, path)
	}

	return result.Data.Data, nil
}

// listKV2 lists keys under a KV v2 path.
func (c *Client) listKV2(ctx context.Context, path string) ([]string, error) {
	if err := c.ensureToken(ctx); err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/v1/%s/metadata/%s/%s", c.addr, c.mount, c.prefix, path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"?list=true", nil)
	if err != nil {
		return nil, err
	}
	req.Method = "LIST"
	req.URL.RawQuery = ""

	c.mu.RLock()
	req.Header.Set("X-Vault-Token", c.token)
	c.mu.RUnlock()

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vault list %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading vault list response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("vault path not found: %s/%s", c.prefix, path)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("vault list returned %d for %s: %s", resp.StatusCode, path, body)
	}

	var result struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parsing vault list response: %w", err)
	}

	return result.Data.Keys, nil
}

// GetEncryptionKey reads the encryption key from Vault at {prefix}/config.
func (c *Client) GetEncryptionKey(ctx context.Context) (string, error) {
	data, err := c.readKV2(ctx, "config")
	if err != nil {
		return "", fmt.Errorf("reading encryption key from vault: %w", err)
	}

	key, ok := data["encryption_key"].(string)
	if !ok || key == "" {
		return "", fmt.Errorf("encryption_key not found or empty in vault secret %s/config", c.prefix)
	}

	return key, nil
}

// GetApp reads a single GitHub App secret from Vault at {prefix}/apps/{slug}.
func (c *Client) GetApp(ctx context.Context, slug string) (*AppSecret, error) {
	if err := validateSlug(slug); err != nil {
		return nil, fmt.Errorf("invalid app slug: %w", err)
	}

	data, err := c.readKV2(ctx, "apps/"+slug)
	if err != nil {
		return nil, fmt.Errorf("reading app %q from vault: %w", slug, err)
	}

	app := &AppSecret{Slug: slug}

	if v, ok := data["app_id"]; ok {
		switch n := v.(type) {
		case float64:
			app.AppID = int64(n)
		case json.Number:
			i, err := n.Int64()
			if err != nil {
				return nil, fmt.Errorf("app %q has invalid app_id %v: %w", slug, n, err)
			}
			app.AppID = i
		case string:
			i, err := strconv.ParseInt(n, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("app %q has non-numeric app_id %q: %w", slug, n, err)
			}
			app.AppID = i
		}
	}
	if v, ok := data["client_id"].(string); ok {
		app.ClientID = v
	}
	if v, ok := data["client_secret"].(string); ok {
		app.ClientSecret = v
	}
	if v, ok := data["private_key"].(string); ok {
		app.PrivateKey = v
	}
	if v, ok := data["enterprise_slug"].(string); ok {
		app.EnterpriseSlug = v
	}
	if v, ok := data["display_name"].(string); ok {
		app.DisplayName = v
	}

	if app.ClientID == "" {
		return nil, fmt.Errorf("app %q missing client_id in vault", slug)
	}
	if app.ClientSecret == "" {
		return nil, fmt.Errorf("app %q missing client_secret in vault", slug)
	}

	if app.DisplayName == "" {
		app.DisplayName = slug
	}

	return app, nil
}

// ListApps discovers all GitHub App slugs stored under {prefix}/apps/.
func (c *Client) ListApps(ctx context.Context) ([]string, error) {
	keys, err := c.listKV2(ctx, "apps")
	if err != nil {
		return nil, fmt.Errorf("listing apps in vault: %w", err)
	}

	// Strip trailing slashes from directory-style keys.
	var slugs []string
	for _, k := range keys {
		k = strings.TrimRight(k, "/")
		if k != "" {
			slugs = append(slugs, k)
		}
	}
	return slugs, nil
}

// LoadAllApps reads all GitHub App secrets from Vault.
func (c *Client) LoadAllApps(ctx context.Context) ([]*AppSecret, error) {
	slugs, err := c.ListApps(ctx)
	if err != nil {
		return nil, err
	}

	if len(slugs) == 0 {
		return nil, fmt.Errorf("no GitHub Apps found in vault at %s/apps/", c.prefix)
	}

	var apps []*AppSecret
	for _, slug := range slugs {
		app, err := c.GetApp(ctx, slug)
		if err != nil {
			return nil, fmt.Errorf("loading app %q: %w", slug, err)
		}
		apps = append(apps, app)
		c.logger.Info("vault_app_loaded", "slug", slug, "app_id", app.AppID, "display_name", app.DisplayName)
	}

	return apps, nil
}
