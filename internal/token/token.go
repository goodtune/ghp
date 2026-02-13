// Package token handles ghp_ token generation and validation.
package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/goodtune/ghp/internal/database"
)

const (
	// Prefix for all proxy tokens.
	Prefix = "ghp_"
	// TokenBytes is the number of random bytes used to generate a token.
	TokenBytes = 32
	// base62 alphabet.
	alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// CreateRequest contains the parameters for creating a new proxy token.
type CreateRequest struct {
	UserID        string
	GitHubTokenID string
	Repository    string
	Scopes        map[string]string
	Duration      time.Duration
	SessionID     string
}

// CreateResult contains the result of creating a new proxy token.
type CreateResult struct {
	Token      string    // The plaintext ghp_ token (shown once).
	ID         string    // The database ID of the token.
	Repository string    // The repository.
	Scopes     map[string]string
	ExpiresAt  time.Time
	SessionID  string
}

// Service manages proxy token lifecycle.
type Service struct {
	store       database.Store
	maxDuration time.Duration
}

// NewService creates a new token Service.
func NewService(store database.Store, maxDuration time.Duration) *Service {
	return &Service{
		store:       store,
		maxDuration: maxDuration,
	}
}

// Create generates a new ghp_ token and stores its hash.
func (s *Service) Create(ctx context.Context, req CreateRequest) (*CreateResult, error) {
	if req.Repository == "" {
		return nil, fmt.Errorf("repository is required")
	}
	if len(req.Scopes) == 0 {
		return nil, fmt.Errorf("at least one scope is required")
	}
	if req.Duration <= 0 {
		return nil, fmt.Errorf("duration must be positive")
	}
	if req.Duration > s.maxDuration {
		return nil, fmt.Errorf("duration %s exceeds maximum %s", req.Duration, s.maxDuration)
	}

	// Generate a cryptographically random token.
	plaintext, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("generating token: %w", err)
	}

	hash := Hash(plaintext)
	prefix := plaintext[:8]

	scopesJSON, err := json.Marshal(req.Scopes)
	if err != nil {
		return nil, fmt.Errorf("marshaling scopes: %w", err)
	}

	expiresAt := time.Now().UTC().Add(req.Duration)

	pt := &database.ProxyToken{
		TokenHash:     hash,
		TokenPrefix:   prefix,
		UserID:        req.UserID,
		GitHubTokenID: req.GitHubTokenID,
		Repository:    req.Repository,
		Scopes:        json.RawMessage(scopesJSON),
		SessionID:     req.SessionID,
		ExpiresAt:     expiresAt,
	}

	if err := s.store.CreateProxyToken(ctx, pt); err != nil {
		return nil, fmt.Errorf("storing token: %w", err)
	}

	return &CreateResult{
		Token:      plaintext,
		ID:         pt.ID,
		Repository: req.Repository,
		Scopes:     req.Scopes,
		ExpiresAt:  expiresAt,
		SessionID:  req.SessionID,
	}, nil
}

// Resolve looks up a proxy token by its plaintext value.
// Returns nil if the token is not found, expired, or revoked.
func (s *Service) Resolve(ctx context.Context, plaintext string) (*database.ProxyToken, error) {
	if !strings.HasPrefix(plaintext, Prefix) {
		return nil, fmt.Errorf("invalid token prefix")
	}

	hash := Hash(plaintext)
	pt, err := s.store.GetProxyTokenByHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("looking up token: %w", err)
	}
	if pt == nil {
		return nil, nil
	}

	if pt.RevokedAt != nil {
		return nil, fmt.Errorf("token has been revoked")
	}
	if time.Now().After(pt.ExpiresAt) {
		return nil, fmt.Errorf("token has expired")
	}

	return pt, nil
}

// Revoke marks a token as revoked.
func (s *Service) Revoke(ctx context.Context, id string) error {
	return s.store.RevokeProxyToken(ctx, id)
}

// RecordUsage updates the last_used_at and request_count fields.
func (s *Service) RecordUsage(ctx context.Context, id string) error {
	return s.store.UpdateProxyTokenUsage(ctx, id)
}

// Hash returns the SHA-256 hex digest of a token string.
func Hash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// generateToken creates a new ghp_-prefixed token with a base62-encoded random value.
func generateToken() (string, error) {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}

	// Convert to base62.
	n := new(big.Int).SetBytes(b)
	base := big.NewInt(int64(len(alphabet)))

	var result []byte
	for n.Sign() > 0 {
		mod := new(big.Int)
		n.DivMod(n, base, mod)
		result = append(result, alphabet[mod.Int64()])
	}

	// Pad to ensure consistent length.
	for len(result) < 43 {
		result = append(result, alphabet[0])
	}

	// Reverse.
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return Prefix + string(result), nil
}

// ParseScopeString parses a comma-separated scope string like "contents:read,pulls:write".
func ParseScopeString(s string) (map[string]string, error) {
	scopes := make(map[string]string)
	parts := strings.Split(s, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid scope format %q (expected permission:level)", part)
		}
		permission := strings.TrimSpace(kv[0])
		level := strings.TrimSpace(kv[1])
		if level != "read" && level != "write" {
			return nil, fmt.Errorf("invalid scope level %q (must be read or write)", level)
		}
		scopes[permission] = level
	}
	if len(scopes) == 0 {
		return nil, fmt.Errorf("no valid scopes provided")
	}
	return scopes, nil
}

// FormatScopes returns a human-readable scope string.
func FormatScopes(scopes map[string]string) string {
	parts := make([]string, 0, len(scopes))
	for k, v := range scopes {
		parts = append(parts, k+":"+v)
	}
	return strings.Join(parts, ", ")
}
