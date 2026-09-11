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

// ErrNotFound is returned by DeleteApp, UpdateApp, UpdateProxyTokenAppID, and
// UpdateProxyTokenScopes when the target record does not exist. Other mutating
// operations (RevokeProxyToken) and all read operations (Get*, List*) do not
// wrap ErrNotFound — reads return (nil, nil) for missing records. Callers can
// distinguish "not found" from other errors using errors.Is(err, ErrNotFound).
var ErrNotFound = errors.New("not found")

// DefaultTokenType is the default ProxyToken.TokenType used when none is
// specified at creation time. This mirrors token.TokenTypeProxy but is
// defined here to avoid a circular import (token → database).
const DefaultTokenType = "proxy"

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
	ExpiresAt *time.Time `json:"expires_at"` // nil means no expiry.
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
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

// CachedRepository represents a repository whose git clone/fetch operations
// are cached locally by the proxy.
type CachedRepository struct {
	ID              string    `json:"id"`
	Owner           string    `json:"owner"`
	Name            string    `json:"name"`
	Enabled         bool      `json:"enabled"`
	TimeoutSeconds  *int      `json:"timeout_seconds,omitempty"`
	MaxCacheSizeMB  *int      `json:"max_cache_size_mb,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Session represents a persisted browser/CLI session. The bearer token
// presented in the Authorization header (or the ghp_session cookie) is
// hashed with SHA-256 before being looked up here, so the database never
// holds raw bearer tokens.
type Session struct {
	TokenHash string    `json:"-"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// OAuthStateKind identifies which OAuth flow an oauth_states row belongs to.
const (
	OAuthStateKindLogin  = "login"
	OAuthStateKindBroker = "broker"
)

// OAuthState captures the per-row payload for an in-flight OAuth state. The
// Kind field selects which payload columns are meaningful: "login" uses
// ReturnTo; "broker" uses BrokerRedirectURI and BrokerDownstreamState.
type OAuthState struct {
	State                 string    `json:"state"`
	Kind                  string    `json:"kind"`
	ReturnTo              string    `json:"return_to"`
	BrokerRedirectURI     string    `json:"broker_redirect_uri"`
	BrokerDownstreamState string    `json:"broker_downstream_state"`
	ExpiresAt             time.Time `json:"expires_at"`
	CreatedAt             time.Time `json:"created_at"`
}

// DeviceAuthStatusPending, DeviceAuthStatusApproved, DeviceAuthStatusDenied
// are the lifecycle states of a CLI device-authorization request. The DB
// CHECK constraint enforces these values; keep them in sync.
const (
	DeviceAuthStatusPending  = "pending"
	DeviceAuthStatusApproved = "approved"
	DeviceAuthStatusDenied   = "denied"
)

// DeviceAuth represents an in-flight CLI device-authorization request. It is
// persisted across the four round-trips that make up the flow (start, poll,
// browser verify, browser decision) so that the request survives load
// balancing in HA deployments — every ghp instance reads the same row.
//
// Lifecycle:
//   - created with Status=pending by POST /cli/auth/device
//   - transitions to approved or denied by POST /cli/auth/decision
//   - deleted by the polling endpoint once the CLI receives the token, or
//     by the cleanup goroutine after ExpiresAt passes
type DeviceAuth struct {
	DeviceCode   string     `json:"device_code"`
	UserCode     string     `json:"user_code"`
	Status       string     `json:"status"`
	SessionToken string     `json:"session_token,omitempty"`
	Username     string     `json:"username,omitempty"`
	LastPolledAt *time.Time `json:"last_polled_at,omitempty"`
	ExpiresAt    time.Time  `json:"expires_at"`
	CreatedAt    time.Time  `json:"created_at"`
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
	// SetDefaultApp atomically marks appID as the default and clears the
	// default flag on all other apps. For SQL backends this runs inside a
	// transaction; for Vault the new default is set before clearing the old
	// one so that a partial failure never leaves the system with no default.
	// Returns ErrNotFound if appID does not exist.
	SetDefaultApp(ctx context.Context, appID string) error

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
	UpdateProxyTokenAppID(ctx context.Context, id string, appID string) error
	// UpdateProxyTokenScopes updates the repositories and scopes of an existing
	// proxy token. Returns ErrNotFound if the token does not exist.
	UpdateProxyTokenScopes(ctx context.Context, id string, repositories json.RawMessage, scopes json.RawMessage) error
	// DeleteExpiredProxyTokens hard-deletes proxy tokens that have been
	// expired or revoked for longer than olderThan.  It returns the number
	// of rows deleted.  Tokens with no expiry (expires_at IS NULL) are only
	// deleted when they have been revoked.  olderThan must be > 0; a zero
	// or negative value is rejected to prevent accidentally deleting active
	// tokens with a future cutoff.
	DeleteExpiredProxyTokens(ctx context.Context, olderThan time.Duration) (int64, error)

	// Cached repositories
	CreateCachedRepository(ctx context.Context, repo *CachedRepository) error
	GetCachedRepositoryByID(ctx context.Context, id string) (*CachedRepository, error)
	GetCachedRepositoryByOwnerName(ctx context.Context, owner, name string) (*CachedRepository, error)
	ListCachedRepositories(ctx context.Context) ([]*CachedRepository, error)
	UpdateCachedRepository(ctx context.Context, repo *CachedRepository) error
	DeleteCachedRepository(ctx context.Context, id string) error

	// Sessions (browser cookie / CLI bearer).
	//
	// CreateSession persists a new session keyed by the SHA-256 hash of the
	// raw bearer token. Callers retain the raw token and present it on
	// subsequent requests; the DB never holds the unhashed value.
	CreateSession(ctx context.Context, s *Session) error
	// GetSessionByTokenHash returns the session for the given hash, or
	// wrapped ErrNotFound if the hash is unknown or its ExpiresAt has
	// passed.
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error)
	// DeleteSession removes the session for the given token hash. No-op
	// (no error) if the row does not exist.
	DeleteSession(ctx context.Context, tokenHash string) error
	// DeleteExpiredSessions removes sessions past their ExpiresAt. Returns
	// the number of rows deleted.
	DeleteExpiredSessions(ctx context.Context) (int64, error)

	// In-flight OAuth state tokens (one-time use, short-lived).
	//
	// CreateOAuthState persists a new state row.
	CreateOAuthState(ctx context.Context, s *OAuthState) error
	// ConsumeOAuthState atomically reads and deletes the state row matching
	// state and kind. Returns wrapped ErrNotFound if the state is unknown,
	// expired, or of a different kind. The atomic consume prevents a state
	// from being replayed if the same callback fires twice.
	ConsumeOAuthState(ctx context.Context, state, kind string) (*OAuthState, error)
	// DeleteExpiredOAuthStates removes oauth_states rows past their
	// ExpiresAt. Returns the number of rows deleted.
	DeleteExpiredOAuthStates(ctx context.Context) (int64, error)

	// CLI device-authorization requests.
	//
	// CreateDeviceAuth inserts a new pending request. It must reject duplicate
	// device_code or user_code values at the database level.
	CreateDeviceAuth(ctx context.Context, da *DeviceAuth) error
	// GetDeviceAuthByDeviceCode looks up a request by the long polling
	// secret. Returns wrapped ErrNotFound if absent. Implementations also
	// return ErrNotFound when the row exists but is past its ExpiresAt — the
	// poll endpoint and cleanup goroutine should treat those identically.
	GetDeviceAuthByDeviceCode(ctx context.Context, deviceCode string) (*DeviceAuth, error)
	// GetDeviceAuthByUserCode is the verification page's lookup. Same
	// not-found / expiry semantics as GetDeviceAuthByDeviceCode.
	GetDeviceAuthByUserCode(ctx context.Context, userCode string) (*DeviceAuth, error)
	// UpdateDeviceAuth persists the in-memory mutation back to storage.
	// Returns ErrNotFound if the device_code does not exist.
	UpdateDeviceAuth(ctx context.Context, da *DeviceAuth) error
	// DeleteDeviceAuth removes a row by device_code. It is a no-op (no error)
	// if the row does not exist; the polling endpoint deletes after handing
	// the token to the CLI and races with the cleanup goroutine.
	DeleteDeviceAuth(ctx context.Context, deviceCode string) error
	// DeleteExpiredDeviceAuths removes all rows whose ExpiresAt is in the
	// past. Returns the number of rows deleted.
	DeleteExpiredDeviceAuths(ctx context.Context) (int64, error)

	// Lifecycle
	Close() error
}

