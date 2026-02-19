package github

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AppConfig holds configuration for GitHub App authentication.
type AppConfig struct {
	AppID      int64
	PrivateKey string // PEM-encoded RSA private key
	BaseURL    string // GitHub API base URL, defaults to https://api.github.com
}

// AppTokenProvider generates GitHub App installation tokens.
type AppTokenProvider struct {
	appID   int64
	key     *rsa.PrivateKey
	baseURL string
	client  *http.Client
	mu      sync.Mutex
	cache   map[int64]cachedToken
}

type cachedToken struct {
	token     string
	expiresAt time.Time
}

// NewAppTokenProvider creates a provider from the given config.
func NewAppTokenProvider(cfg AppConfig) (*AppTokenProvider, error) {
	block, _ := pem.Decode([]byte(cfg.PrivateKey))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	var key *rsa.PrivateKey
	var err error

	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, fmt.Errorf("parsing PKCS8 private key: %w", e)
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS8 key is not RSA")
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return &AppTokenProvider{
		appID:   cfg.AppID,
		key:     key,
		baseURL: baseURL,
		client:  &http.Client{Timeout: 30 * time.Second},
		cache:   make(map[int64]cachedToken),
	}, nil
}

// GetInstallationToken returns a GitHub installation token for the given
// installation, scoped to the specified repositories and permissions.
// Results are cached until 5 minutes before expiry.
func (p *AppTokenProvider) GetInstallationToken(ctx context.Context, installationID int64, repos []string, permissions map[string]string) (string, error) {
	p.mu.Lock()
	if ct, ok := p.cache[installationID]; ok && time.Now().Before(ct.expiresAt.Add(-5*time.Minute)) {
		p.mu.Unlock()
		return ct.token, nil
	}
	p.mu.Unlock()

	// Generate JWT.
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    fmt.Sprintf("%d", p.appID),
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := jwtToken.SignedString(p.key)
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	// Request installation token.
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", p.baseURL, installationID)

	body := map[string]interface{}{
		"repositories": repos,
		"permissions":  permissions,
	}
	bodyJSON, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyJSON))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+signed)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting installation token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("installation token request failed (%d): %s", resp.StatusCode, respBody)
	}

	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}

	// Cache.
	p.mu.Lock()
	p.cache[installationID] = cachedToken{token: result.Token, expiresAt: result.ExpiresAt}
	p.mu.Unlock()

	return result.Token, nil
}
