// Package token manages the lifecycle of ghp proxy tokens (ghx_ and gha_
// prefixed). It provides creation, hash-based resolution, revocation, and usage
// tracking. Tokens are never stored in plaintext — only their SHA-256 hash is
// persisted. The plaintext is returned once at creation time and cannot be
// recovered from the database.
//
// Two token types are supported:
//   - Proxy tokens (ghx_): backed by a user's GitHub OAuth credential.
//   - Agent tokens (gha_): backed by a GitHub App installation, for automated workflows.
package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/goodtune/ghp/internal/database"
)

const (
	// tokenCacheTTL is how long a resolved token is kept in the in-memory
	// cache before being re-fetched from the database. A short TTL ensures
	// that revocations and expiry propagate promptly even in multi-instance
	// deployments where one instance's Revoke() call doesn't reach others.
	tokenCacheTTL = 30 * time.Second
)

// cachedToken pairs a resolved proxy token with the wall-clock time it was
// stored so that stale entries can be evicted on read.
type cachedToken struct {
	token    *database.ProxyToken
	cachedAt time.Time
}

// TokenType distinguishes proxy tokens from agent tokens.
type TokenType string

const (
	TokenTypeProxy TokenType = "proxy"
	TokenTypeAgent TokenType = "agent"
)

// Prefix constants for each token type.
const (
	PrefixProxy = "ghx_"
	PrefixAgent = "gha_"
	TokenBytes  = 32
	alphabet    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// tokenPrefixes maps token types to their string prefixes.
var tokenPrefixes = map[TokenType]string{
	TokenTypeProxy: PrefixProxy,
	TokenTypeAgent: PrefixAgent,
}

// TokenTypeFromPrefix returns the token type for a given prefixed string.
func TokenTypeFromPrefix(s string) (TokenType, bool) {
	for tt, prefix := range tokenPrefixes {
		if strings.HasPrefix(s, prefix) {
			return tt, true
		}
	}
	return "", false
}

// PrefixForType returns the prefix for a given token type.
func PrefixForType(tt TokenType) string {
	return tokenPrefixes[tt]
}

// CreateRequest contains the parameters for creating a new token.
type CreateRequest struct {
	TokenType      TokenType
	AppRecordID    string            // App record ID for agent tokens (empty = default app).
	UserID         string
	GitHubTokenID  string            // Required for proxy tokens.
	InstallationID int64             // Required for agent tokens.
	Repository     string            // Deprecated: use Repositories instead.
	Repositories   []string          // Optional — open-scoped (all repos) if empty.
	Scopes         map[string]string // Optional — open-scoped if empty.
	Duration       time.Duration
	NoExpiry       bool // When true, create a token that never expires. Requires AllowNoExpiry config.
	SessionID      string
}

// CreateResult contains the result of creating a new token.
type CreateResult struct {
	Token        string
	ID           string
	TokenType    TokenType
	Repositories []string
	Scopes       map[string]string
	ExpiresAt    *time.Time // nil when the token has no expiry.
	SessionID    string
}

// Service manages proxy token lifecycle.
type Service struct {
	store         database.Store
	maxDuration   time.Duration
	allowNoExpiry bool

	// tokenCache is an in-memory cache of resolved proxy tokens keyed by
	// SHA-256 hex digest (the same key used for database lookups). Entries
	// expire after tokenCacheTTL to bound staleness from revocations that
	// happen on other instances.
	tokenCache sync.Map // map[string]cachedToken

	// idToHash maps token ID → token hash so that Revoke (which receives an
	// ID) can invalidate the corresponding cache entry without a DB lookup.
	idToHash sync.Map // map[string]string

	// nowFunc is the time source used for TTL checks. It defaults to
	// time.Now and can be overridden in tests.
	nowFunc func() time.Time
}

// NewService creates a new token Service.
func NewService(store database.Store, maxDuration time.Duration, allowNoExpiry bool) *Service {
	return &Service{
		store:         store,
		maxDuration:   maxDuration,
		allowNoExpiry: allowNoExpiry,
		nowFunc:       time.Now,
	}
}

// Create generates a new token and stores its hash.
func (s *Service) Create(ctx context.Context, req CreateRequest) (*CreateResult, error) {
	tt := req.TokenType
	if tt == "" {
		tt = TokenTypeProxy
	}

	// Build repositories list.
	var repos []string
	switch tt {
	case TokenTypeProxy:
		// Proxy tokens are open-scoped by default — repositories are optional.
		if req.Repository != "" {
			repos = []string{req.Repository}
		}
		if len(req.Repositories) > 0 {
			repos = req.Repositories
		}
	case TokenTypeAgent:
		if req.InstallationID == 0 {
			return nil, fmt.Errorf("installation_id is required for agent tokens")
		}
		repos = req.Repositories
	default:
		return nil, fmt.Errorf("unknown token type %q", tt)
	}

	// Scopes are optional — an empty map means the token is open-scoped
	// and carries the full permissions of the underlying credential.
	if req.NoExpiry {
		if !s.allowNoExpiry {
			return nil, fmt.Errorf("no-expiry tokens are not allowed by server configuration")
		}
	} else {
		if req.Duration <= 0 {
			return nil, fmt.Errorf("duration must be positive")
		}
		if req.Duration > s.maxDuration {
			return nil, fmt.Errorf("duration %s exceeds maximum %s", req.Duration, s.maxDuration)
		}
	}

	plaintext, err := generateToken(tt)
	if err != nil {
		return nil, fmt.Errorf("generating token: %w", err)
	}

	hash := Hash(plaintext)
	prefix := plaintext[:8]

	// Marshal scopes — nil/empty map becomes JSON null.
	var scopesJSON []byte
	if len(req.Scopes) > 0 {
		scopesJSON, err = json.Marshal(req.Scopes)
		if err != nil {
			return nil, fmt.Errorf("marshaling scopes: %w", err)
		}
	} else {
		scopesJSON = []byte("null")
	}

	// Marshal repositories — nil/empty slice becomes JSON null.
	var reposJSON []byte
	if len(repos) > 0 {
		reposJSON, err = json.Marshal(repos)
		if err != nil {
			return nil, fmt.Errorf("marshaling repositories: %w", err)
		}
	} else {
		reposJSON = []byte("null")
	}

	var expiresAt *time.Time
	if !req.NoExpiry {
		t := time.Now().UTC().Add(req.Duration)
		expiresAt = &t
	}

	pt := &database.ProxyToken{
		TokenHash:    hash,
		TokenPrefix:  prefix,
		TokenType:    string(tt),
		Repositories: json.RawMessage(reposJSON),
		Scopes:       json.RawMessage(scopesJSON),
		SessionID:    req.SessionID,
		ExpiresAt:    expiresAt,
	}

	// Set type-specific fields.
	if req.UserID != "" {
		pt.UserID = &req.UserID
	}
	if req.GitHubTokenID != "" {
		pt.GitHubTokenID = &req.GitHubTokenID
	}
	if req.InstallationID != 0 {
		pt.InstallationID = &req.InstallationID
	}
	// AppRecordID only applies to agent tokens; proxy tokens resolve
	// credentials via the linked GitHubToken, not an app record.
	if req.AppRecordID != "" && tt == TokenTypeAgent {
		pt.AppID = &req.AppRecordID
	}

	if err := s.store.CreateProxyToken(ctx, pt); err != nil {
		return nil, fmt.Errorf("storing token: %w", err)
	}

	return &CreateResult{
		Token:        plaintext,
		ID:           pt.ID,
		TokenType:    tt,
		Repositories: repos,
		Scopes:       req.Scopes,
		ExpiresAt:    expiresAt,
		SessionID:    req.SessionID,
	}, nil
}

// Resolve looks up a proxy token by its plaintext value.
// Returns nil if the token is not found, expired, or revoked.
//
// An in-memory cache keyed by the token's SHA-256 hash avoids a database
// round-trip on every proxied request. Cached entries are evicted after
// tokenCacheTTL (30 s) so that revocations and expiry propagate promptly.
func (s *Service) Resolve(ctx context.Context, plaintext string) (*database.ProxyToken, error) {
	if _, ok := TokenTypeFromPrefix(plaintext); !ok {
		return nil, fmt.Errorf("invalid token prefix")
	}

	hash := Hash(plaintext)
	now := s.nowFunc()

	// Check the in-memory cache first.
	if entry, ok := s.tokenCache.Load(hash); ok {
		ct := entry.(cachedToken)
		if now.Sub(ct.cachedAt) < tokenCacheTTL {
			pt := ct.token
			if pt.RevokedAt != nil {
				return nil, fmt.Errorf("token has been revoked")
			}
			if pt.ExpiresAt != nil && now.After(*pt.ExpiresAt) {
				return nil, fmt.Errorf("token has expired")
			}
			return pt, nil
		}
		// TTL expired — evict and fall through to the database.
		s.tokenCache.Delete(hash)
	}

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
	if pt.ExpiresAt != nil && now.After(*pt.ExpiresAt) {
		return nil, fmt.Errorf("token has expired")
	}

	// Cache the valid token for subsequent requests.
	s.cacheToken(hash, pt)

	return pt, nil
}

// Revoke marks a token as revoked and removes it from the in-memory cache
// so that subsequent Resolve calls see the revocation immediately on this
// instance (other instances will see it when their cached entry expires).
func (s *Service) Revoke(ctx context.Context, id string) error {
	if err := s.store.RevokeProxyToken(ctx, id); err != nil {
		return err
	}
	// Invalidate the cache entry. The id→hash secondary index lets us find
	// the cache key without an extra database lookup.
	if hashVal, ok := s.idToHash.LoadAndDelete(id); ok {
		s.tokenCache.Delete(hashVal.(string))
	}
	return nil
}

// cacheToken stores a proxy token in the in-memory cache and records the
// id→hash mapping so Revoke can invalidate by ID.
func (s *Service) cacheToken(hash string, pt *database.ProxyToken) {
	s.tokenCache.Store(hash, cachedToken{
		token:    pt,
		cachedAt: s.nowFunc(),
	})
	s.idToHash.Store(pt.ID, hash)
}

// WarmTokenCache pre-loads all active (unexpired, non-revoked) proxy tokens
// into the in-memory cache so the first request for each token avoids a
// database round-trip. This is best-effort: errors are logged and skipped.
func (s *Service) WarmTokenCache(ctx context.Context, logger *slog.Logger) {
	tokens, err := s.store.ListActiveProxyTokens(ctx)
	if err != nil {
		if logger != nil {
			logger.Error("token cache warm: failed to list active tokens", "error", err)
		}
		return
	}
	loaded := 0
	for _, pt := range tokens {
		if pt.TokenHash == "" {
			continue
		}
		s.cacheToken(pt.TokenHash, pt)
		loaded++
	}
	if logger != nil {
		logger.Info("token cache warmed", "tokens", loaded)
	}
}

// Hash returns the SHA-256 hex digest of a token string.
func Hash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// generateToken creates a new prefixed token with a base62-encoded random value.
func generateToken(tt TokenType) (string, error) {
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

	return PrefixForType(tt) + string(result), nil
}

// ParseScopeString parses a comma-separated scope string like "contents:read,pull_requests:write".
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
