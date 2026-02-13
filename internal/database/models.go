// Package database provides the data access layer for ghp.
package database

import (
	"context"
	"encoding/json"
	"time"
)

// User represents a ghp user authenticated via GitHub OAuth.
type User struct {
	ID             string    `json:"id"`
	GitHubID       int64     `json:"github_id"`
	GitHubUsername  string    `json:"github_username"`
	GitHubEmail    string    `json:"github_email"`
	Role           string    `json:"role"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// GitHubToken stores an encrypted GitHub OAuth token pair.
type GitHubToken struct {
	ID                    string    `json:"id"`
	UserID                string    `json:"user_id"`
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	Scopes                string    `json:"scopes"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// ProxyToken represents a ghp_ token issued to agents.
type ProxyToken struct {
	ID            string          `json:"id"`
	TokenHash     string          `json:"-"`
	TokenPrefix   string          `json:"token_prefix"`
	UserID        string          `json:"user_id"`
	GitHubTokenID string          `json:"github_token_id"`
	Repository    string          `json:"repository"`
	Scopes        json.RawMessage `json:"scopes"`
	SessionID     string          `json:"session_id"`
	ExpiresAt     time.Time       `json:"expires_at"`
	RevokedAt     *time.Time      `json:"revoked_at,omitempty"`
	LastUsedAt    *time.Time      `json:"last_used_at,omitempty"`
	RequestCount  int64           `json:"request_count"`
	CreatedAt     time.Time       `json:"created_at"`
}

// AuditEntry represents an entry in the audit log.
type AuditEntry struct {
	ID           string          `json:"id"`
	Timestamp    time.Time       `json:"timestamp"`
	UserID       string          `json:"user_id"`
	ProxyTokenID *string         `json:"proxy_token_id,omitempty"`
	Action       string          `json:"action"`
	Method       string          `json:"method,omitempty"`
	Path         string          `json:"path,omitempty"`
	Repository   string          `json:"repository,omitempty"`
	StatusCode   int             `json:"status_code,omitempty"`
	DurationMS   int             `json:"duration_ms,omitempty"`
	SessionID    string          `json:"session_id,omitempty"`
	Metadata     json.RawMessage `json:"metadata,omitempty"`
}

// Scopes represents a map of permission to access level.
type Scopes map[string]string

// ParseScopes parses a JSON-encoded scopes value.
func ParseScopes(data json.RawMessage) (Scopes, error) {
	var s Scopes
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, err
	}
	return s, nil
}

// HasPermission checks if the scopes include the given permission at the required level.
// A "write" scope also grants "read" access.
func (s Scopes) HasPermission(permission, level string) bool {
	granted, ok := s[permission]
	if !ok {
		return false
	}
	if level == "read" {
		return granted == "read" || granted == "write"
	}
	return granted == level
}

// Store defines the database operations for ghp.
type Store interface {
	// Users
	UpsertUser(ctx context.Context, user *User) error
	GetUserByGitHubID(ctx context.Context, githubID int64) (*User, error)
	GetUserByID(ctx context.Context, id string) (*User, error)
	ListUsers(ctx context.Context) ([]*User, error)

	// GitHub tokens
	UpsertGitHubToken(ctx context.Context, token *GitHubToken) error
	GetGitHubToken(ctx context.Context, userID string) (*GitHubToken, error)
	GetGitHubTokenByID(ctx context.Context, id string) (*GitHubToken, error)

	// Proxy tokens
	CreateProxyToken(ctx context.Context, token *ProxyToken) error
	GetProxyTokenByHash(ctx context.Context, hash string) (*ProxyToken, error)
	GetProxyTokenByID(ctx context.Context, id string) (*ProxyToken, error)
	ListProxyTokens(ctx context.Context, userID string) ([]*ProxyToken, error)
	ListAllProxyTokens(ctx context.Context) ([]*ProxyToken, error)
	RevokeProxyToken(ctx context.Context, id string) error
	UpdateProxyTokenUsage(ctx context.Context, id string) error

	// Audit log
	CreateAuditEntry(ctx context.Context, entry *AuditEntry) error
	ListAuditEntries(ctx context.Context, filter AuditFilter) ([]*AuditEntry, error)

	// Lifecycle
	Close() error
}

// AuditFilter defines criteria for querying the audit log.
type AuditFilter struct {
	UserID     string
	Repository string
	TokenID    string
	Action     string
	StatusCode int
	Limit      int
	Offset     int
}
