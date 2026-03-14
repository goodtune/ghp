// Package database provides the data access layer for ghp, abstracting over
// PostgreSQL (production) and SQLite (development) backends. It defines the
// Store interface for all database operations, the data models (User,
// GitHubToken, ProxyToken), and the migration system. Both
// drivers are pure Go (no CGO) — SQLite via modernc.org/sqlite and PostgreSQL
// via pgx.
package database

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// ErrNotFound is returned by mutating store operations (Delete, Update) when
// the target record does not exist. Read operations (Get*, List*) return
// (nil, nil) for missing records. Callers can distinguish "not found" from
// other errors using errors.Is(err, ErrNotFound).
var ErrNotFound = errors.New("not found")

// App represents a GitHub App configured in the proxy.
type App struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	AppID        int64     `json:"app_id"`
	ClientID     string    `json:"client_id"`
	ClientSecret string    `json:"client_secret"`
	PrivateKey   string    `json:"private_key"`
	BaseURL      string    `json:"base_url"`
	IsDefault    bool      `json:"is_default"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

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
	AppID                 *string   `json:"app_id,omitempty"`
	AccessToken           string    `json:"access_token"`
	RefreshToken          string    `json:"refresh_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	Scopes                string    `json:"scopes"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// ProxyToken represents a ghx_ or gha_ token issued to agents.
type ProxyToken struct {
	ID             string          `json:"id"`
	TokenHash      string          `json:"-"`
	TokenPrefix    string          `json:"token_prefix"`
	TokenType      string          `json:"token_type"`
	AppID          *string         `json:"app_id,omitempty"`
	UserID         *string         `json:"user_id,omitempty"`
	GitHubTokenID  *string         `json:"github_token_id,omitempty"`
	InstallationID *int64          `json:"installation_id,omitempty"`
	Repositories   json.RawMessage `json:"repositories"`
	Scopes         json.RawMessage `json:"scopes"`
	SessionID      string          `json:"session_id"`
	ExpiresAt      time.Time       `json:"expires_at"`
	RevokedAt      *time.Time      `json:"revoked_at,omitempty"`
	LastUsedAt     *time.Time      `json:"last_used_at,omitempty"`
	RequestCount   int64           `json:"request_count"`
	CreatedAt      time.Time       `json:"created_at"`
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
	// Apps
	CreateApp(ctx context.Context, app *App) error
	GetAppByID(ctx context.Context, id string) (*App, error)
	GetDefaultApp(ctx context.Context) (*App, error)
	ListApps(ctx context.Context) ([]*App, error)
	UpdateApp(ctx context.Context, app *App) error
	DeleteApp(ctx context.Context, id string) error

	// Users
	UpsertUser(ctx context.Context, user *User) error
	GetUserByGitHubID(ctx context.Context, githubID int64) (*User, error)
	GetUserByID(ctx context.Context, id string) (*User, error)
	ListUsers(ctx context.Context) ([]*User, error)
	SyncAdminRoles(ctx context.Context, adminUsernames []string) error

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
	ListActiveProxyTokens(ctx context.Context) ([]*ProxyToken, error)
	RevokeProxyToken(ctx context.Context, id string) error
	UpdateProxyTokenUsage(ctx context.Context, id string) error
	UpdateProxyTokenAppID(ctx context.Context, id string, appID string) error

	// Lifecycle
	Close() error
}

