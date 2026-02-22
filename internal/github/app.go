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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// InstallationTokenError represents a failed installation token request,
// carrying the upstream HTTP status code, GitHub's error message, and
// permission diagnostics.
type InstallationTokenError struct {
	StatusCode           int
	Message              string
	RequestedPermissions map[string]string
	GrantedPermissions   map[string]string
}

func (e *InstallationTokenError) Error() string {
	missing := e.MissingPermissions()
	if len(missing) == 0 {
		return fmt.Sprintf("installation token request failed (%d): %s", e.StatusCode, e.Message)
	}

	parts := make([]string, 0, len(missing))
	for perm, level := range missing {
		parts = append(parts, perm+":"+level)
	}
	sort.Strings(parts)
	return fmt.Sprintf("installation token request failed (%d): %s (missing permissions: %s)",
		e.StatusCode, e.Message, strings.Join(parts, ", "))
}

// MissingPermissions returns the permissions that were requested but not
// granted (or granted at a lower level than requested).
func (e *InstallationTokenError) MissingPermissions() map[string]string {
	missing := make(map[string]string)
	for perm, reqLevel := range e.RequestedPermissions {
		grantedLevel, ok := e.GrantedPermissions[perm]
		if !ok || !permissionSatisfies(grantedLevel, reqLevel) {
			missing[perm] = reqLevel
		}
	}
	return missing
}

// permissionSatisfies returns true if granted >= requested.
// GitHub permission levels: "read" < "write" < "admin".
func permissionSatisfies(granted, requested string) bool {
	levels := map[string]int{"read": 1, "write": 2, "admin": 3}
	return levels[granted] >= levels[requested]
}

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
	signed, err := p.signJWT()
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

		// Parse GitHub's error message.
		var ghErr struct {
			Message string `json:"message"`
		}
		msg := string(respBody)
		if json.Unmarshal(respBody, &ghErr) == nil && ghErr.Message != "" {
			msg = ghErr.Message
		}

		// Optionally fetch granted permissions to provide diagnostics.
		var grantedPerms map[string]string
		if resp.StatusCode == http.StatusUnprocessableEntity {
			if granted, err := p.getInstallationPermissions(ctx, signed, installationID); err == nil {
				grantedPerms = granted
			}
		}

		return "", &InstallationTokenError{
			StatusCode:           resp.StatusCode,
			Message:              msg,
			RequestedPermissions: permissions,
			GrantedPermissions:   grantedPerms,
		}
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

// getInstallationPermissions queries the GitHub API for the permissions
// granted to the given installation. The jwtToken must be a valid App JWT.
func (p *AppTokenProvider) getInstallationPermissions(ctx context.Context, jwtToken string, installationID int64) (map[string]string, error) {
	url := fmt.Sprintf("%s/app/installations/%d", p.baseURL, installationID)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating installation request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching installation: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("installation request failed (%d)", resp.StatusCode)
	}

	var result struct {
		Permissions map[string]string `json:"permissions"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding installation response: %w", err)
	}

	return result.Permissions, nil
}

// Installation represents a GitHub App installation.
type Installation struct {
	ID      int64                `json:"id"`
	Account InstallationAccount  `json:"account"`
	Permissions map[string]string `json:"permissions"`
	RepositorySelection string   `json:"repository_selection"`
}

// InstallationAccount is the GitHub account (user or org) associated with an installation.
type InstallationAccount struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Type  string `json:"type"`
}

// InstallationRepository represents a repository accessible to an installation.
type InstallationRepository struct {
	FullName string `json:"full_name"`
	Name     string `json:"name"`
	Private  bool   `json:"private"`
}

// ListInstallations returns all installations for this GitHub App.
func (p *AppTokenProvider) ListInstallations(ctx context.Context) ([]Installation, error) {
	signed, err := p.signJWT()
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/app/installations", p.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+signed)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("listing installations: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("list installations failed (%d): %s", resp.StatusCode, string(body))
	}

	var installations []Installation
	if err := json.NewDecoder(resp.Body).Decode(&installations); err != nil {
		return nil, fmt.Errorf("decoding installations: %w", err)
	}
	return installations, nil
}

// ListInstallationRepositories returns repositories accessible to the given installation.
func (p *AppTokenProvider) ListInstallationRepositories(ctx context.Context, installationID int64) ([]InstallationRepository, error) {
	// Get an unscoped installation token to list repos.
	signed, err := p.signJWT()
	if err != nil {
		return nil, err
	}

	tokenURL := fmt.Sprintf("%s/app/installations/%d/access_tokens", p.baseURL, installationID)
	tokenReq, err := http.NewRequestWithContext(ctx, "POST", tokenURL, bytes.NewReader([]byte("{}")))
	if err != nil {
		return nil, fmt.Errorf("creating token request: %w", err)
	}
	tokenReq.Header.Set("Authorization", "Bearer "+signed)
	tokenReq.Header.Set("Accept", "application/vnd.github+json")
	tokenReq.Header.Set("Content-Type", "application/json")

	tokenResp, err := p.client.Do(tokenReq)
	if err != nil {
		return nil, fmt.Errorf("requesting installation token: %w", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(tokenResp.Body)
		return nil, fmt.Errorf("installation token request failed (%d): %s", tokenResp.StatusCode, string(body))
	}

	var tokenResult struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokenResult); err != nil {
		return nil, fmt.Errorf("decoding token: %w", err)
	}

	// Paginate through all repos.
	var allRepos []InstallationRepository
	repoURL := fmt.Sprintf("%s/installation/repositories?per_page=100", p.baseURL)

	for repoURL != "" {
		req, err := http.NewRequestWithContext(ctx, "GET", repoURL, nil)
		if err != nil {
			return nil, fmt.Errorf("creating repo request: %w", err)
		}
		req.Header.Set("Authorization", "token "+tokenResult.Token)
		req.Header.Set("Accept", "application/vnd.github+json")

		resp, err := p.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("listing repos: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("list repos failed (%d): %s", resp.StatusCode, string(body))
		}

		var page struct {
			Repositories []InstallationRepository `json:"repositories"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decoding repos: %w", err)
		}
		resp.Body.Close()

		allRepos = append(allRepos, page.Repositories...)

		// Follow pagination.
		repoURL = ParseLinkNext(resp.Header.Get("Link"))
	}

	return allRepos, nil
}

// signJWT creates a signed JWT for GitHub App authentication.
func (p *AppTokenProvider) signJWT() (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    fmt.Sprintf("%d", p.appID),
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return jwtToken.SignedString(p.key)
}

// ParseLinkNext extracts the "next" URL from a GitHub Link header.
func ParseLinkNext(header string) string {
	if header == "" {
		return ""
	}
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if strings.Contains(part, `rel="next"`) {
			start := strings.Index(part, "<")
			end := strings.Index(part, ">")
			if start >= 0 && end > start {
				return part[start+1 : end]
			}
		}
	}
	return ""
}
