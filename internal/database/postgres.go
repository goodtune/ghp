package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// PostgresStore implements Store using PostgreSQL.
type PostgresStore struct {
	db *sql.DB
}

// NewPostgresStore opens a PostgreSQL database with the given DSN.
func NewPostgresStore(dsn string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening postgres: %w", err)
	}

	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("pinging postgres: %w", err)
	}

	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}

// --- Migration support ---

func (s *PostgresStore) EnsureMigrationsTable(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	return err
}

func (s *PostgresStore) AppliedMigrations(ctx context.Context) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM schema_migrations ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	return names, rows.Err()
}

func (s *PostgresStore) RunMigration(ctx context.Context, name, sqlStr string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, sqlStr); err != nil {
		return fmt.Errorf("executing migration SQL: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (name) VALUES ($1)`, name); err != nil {
		return fmt.Errorf("recording migration: %w", err)
	}

	return tx.Commit()
}

// --- Users ---

func (s *PostgresStore) UpsertUser(ctx context.Context, user *User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	now := time.Now().UTC()
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO users (id, github_id, github_username, github_email, role, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT(github_id) DO UPDATE SET
			github_username = EXCLUDED.github_username,
			github_email = EXCLUDED.github_email,
			role = EXCLUDED.role,
			updated_at = EXCLUDED.updated_at
		RETURNING id, role, created_at, updated_at
	`, user.ID, user.GitHubID, user.GitHubUsername, user.GitHubEmail, user.Role, now, now,
	).Scan(&user.ID, &user.Role, &user.CreatedAt, &user.UpdatedAt)
	return err
}

func (s *PostgresStore) SyncAdminRoles(ctx context.Context, adminUsernames []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().UTC()

	// Demote all current admins to 'user'.
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET role = 'user', updated_at = $1 WHERE role = 'admin'`, now,
	); err != nil {
		return err
	}

	// Promote the configured admins.
	for _, username := range adminUsernames {
		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET role = 'admin', updated_at = $1 WHERE LOWER(github_username) = LOWER($2)`,
			now, username,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) GetUserByGitHubID(ctx context.Context, githubID int64) (*User, error) {
	u := &User{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, github_id, github_username, github_email, role, created_at, updated_at FROM users WHERE github_id = $1`,
		githubID,
	).Scan(&u.ID, &u.GitHubID, &u.GitHubUsername, &u.GitHubEmail, &u.Role, &u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *PostgresStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	u := &User{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, github_id, github_username, github_email, role, created_at, updated_at FROM users WHERE id = $1`,
		id,
	).Scan(&u.ID, &u.GitHubID, &u.GitHubUsername, &u.GitHubEmail, &u.Role, &u.CreatedAt, &u.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *PostgresStore) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, github_id, github_username, github_email, role, created_at, updated_at FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u := &User{}
		if err := rows.Scan(&u.ID, &u.GitHubID, &u.GitHubUsername, &u.GitHubEmail, &u.Role, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// --- GitHub Tokens ---

func (s *PostgresStore) UpsertGitHubToken(ctx context.Context, token *GitHubToken) error {
	if token.ID == "" {
		token.ID = uuid.New().String()
	}
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO github_tokens (id, user_id, app_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at, scopes, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT(user_id) DO UPDATE SET
			access_token = EXCLUDED.access_token,
			refresh_token = EXCLUDED.refresh_token,
			access_token_expires_at = EXCLUDED.access_token_expires_at,
			refresh_token_expires_at = EXCLUDED.refresh_token_expires_at,
			scopes = EXCLUDED.scopes,
			app_id = EXCLUDED.app_id,
			updated_at = EXCLUDED.updated_at
	`, token.ID, token.UserID, token.AppID, token.AccessToken, token.RefreshToken,
		token.AccessTokenExpiresAt, token.RefreshTokenExpiresAt,
		token.Scopes, now, now)
	return err
}

func (s *PostgresStore) GetGitHubToken(ctx context.Context, userID string) (*GitHubToken, error) {
	t := &GitHubToken{}
	var appID sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, app_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at, scopes, created_at, updated_at
		 FROM github_tokens WHERE user_id = $1 ORDER BY updated_at DESC LIMIT 1`, userID,
	).Scan(&t.ID, &t.UserID, &appID, &t.AccessToken, &t.RefreshToken, &t.AccessTokenExpiresAt, &t.RefreshTokenExpiresAt, &t.Scopes, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if appID.Valid {
		t.AppID = &appID.String
	}
	return t, nil
}

func (s *PostgresStore) GetGitHubTokenByID(ctx context.Context, id string) (*GitHubToken, error) {
	t := &GitHubToken{}
	var appID sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, app_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at, scopes, created_at, updated_at
		 FROM github_tokens WHERE id = $1`, id,
	).Scan(&t.ID, &t.UserID, &appID, &t.AccessToken, &t.RefreshToken, &t.AccessTokenExpiresAt, &t.RefreshTokenExpiresAt, &t.Scopes, &t.CreatedAt, &t.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if appID.Valid {
		t.AppID = &appID.String
	}
	return t, nil
}

// --- Proxy Tokens ---

func (s *PostgresStore) CreateProxyToken(ctx context.Context, token *ProxyToken) error {
	if token.ID == "" {
		token.ID = uuid.New().String()
	}
	now := time.Now().UTC()
	scopesJSON, err := json.Marshal(token.Scopes)
	if err != nil {
		return fmt.Errorf("marshaling scopes: %w", err)
	}
	reposJSON, err := json.Marshal(token.Repositories)
	if err != nil {
		return fmt.Errorf("marshaling repositories: %w", err)
	}
	tokenType := token.TokenType
	if tokenType == "" {
		tokenType = DefaultTokenType
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO proxy_tokens (id, token_hash, token_prefix, token_type, app_id, user_id, github_token_id, installation_id, repositories, scopes, session_id, expires_at, request_count, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 0, $13)
	`, token.ID, token.TokenHash, token.TokenPrefix, tokenType, token.AppID, token.UserID, token.GitHubTokenID,
		token.InstallationID, string(reposJSON), string(scopesJSON), token.SessionID,
		token.ExpiresAt, now)
	return err
}

func scanPostgresProxyToken(scan func(dest ...interface{}) error) (*ProxyToken, error) {
	t := &ProxyToken{}
	var scopesStr, reposStr string
	var revokedAt, lastUsedAt sql.NullTime
	var appID, userID, githubTokenID sql.NullString
	var installationID sql.NullInt64
	err := scan(&t.ID, &t.TokenHash, &t.TokenPrefix, &t.TokenType, &appID, &userID, &githubTokenID, &installationID, &reposStr, &scopesStr,
		&t.SessionID, &t.ExpiresAt, &revokedAt, &lastUsedAt, &t.RequestCount, &t.CreatedAt)
	if err != nil {
		return nil, err
	}
	t.Scopes = json.RawMessage(scopesStr)
	t.Repositories = json.RawMessage(reposStr)
	if appID.Valid {
		t.AppID = &appID.String
	}
	if userID.Valid {
		t.UserID = &userID.String
	}
	if githubTokenID.Valid {
		t.GitHubTokenID = &githubTokenID.String
	}
	if installationID.Valid {
		t.InstallationID = &installationID.Int64
	}
	if revokedAt.Valid {
		t.RevokedAt = &revokedAt.Time
	}
	if lastUsedAt.Valid {
		t.LastUsedAt = &lastUsedAt.Time
	}
	return t, nil
}

const pgProxyTokenCols = `id, token_hash, token_prefix, token_type, app_id, user_id, github_token_id, installation_id, repositories, scopes, session_id, expires_at, revoked_at, last_used_at, request_count, created_at`

func (s *PostgresStore) GetProxyTokenByHash(ctx context.Context, hash string) (*ProxyToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+pgProxyTokenCols+` FROM proxy_tokens WHERE token_hash = $1`, hash)
	t, err := scanPostgresProxyToken(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

func (s *PostgresStore) GetProxyTokenByID(ctx context.Context, id string) (*ProxyToken, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT `+pgProxyTokenCols+` FROM proxy_tokens WHERE id = $1`, id)
	t, err := scanPostgresProxyToken(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

func (s *PostgresStore) ListProxyTokens(ctx context.Context, userID string) ([]*ProxyToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+pgProxyTokenCols+` FROM proxy_tokens WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPostgresProxyTokenRows(rows)
}

func (s *PostgresStore) ListAllProxyTokens(ctx context.Context) ([]*ProxyToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+pgProxyTokenCols+` FROM proxy_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPostgresProxyTokenRows(rows)
}

func (s *PostgresStore) ListActiveProxyTokens(ctx context.Context) ([]*ProxyToken, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+pgProxyTokenCols+` FROM proxy_tokens WHERE revoked_at IS NULL AND expires_at > NOW() ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPostgresProxyTokenRows(rows)
}

func scanPostgresProxyTokenRows(rows *sql.Rows) ([]*ProxyToken, error) {
	var tokens []*ProxyToken
	for rows.Next() {
		t, err := scanPostgresProxyToken(rows.Scan)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func (s *PostgresStore) RevokeProxyToken(ctx context.Context, id string) error {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `UPDATE proxy_tokens SET revoked_at = $1 WHERE id = $2 AND revoked_at IS NULL`, now, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("token not found or already revoked")
	}
	return nil
}

func (s *PostgresStore) UpdateProxyTokenUsage(ctx context.Context, id string) error {
	now := time.Now().UTC()
	_, err := s.db.ExecContext(ctx,
		`UPDATE proxy_tokens SET last_used_at = $1, request_count = request_count + 1 WHERE id = $2`, now, id)
	return err
}

func (s *PostgresStore) UpdateProxyTokenAppID(ctx context.Context, id string, appID string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE proxy_tokens SET app_id = $1 WHERE id = $2`, appID, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("proxy token %s: %w", id, ErrNotFound)
	}
	return nil
}

// --- Apps ---

func (s *PostgresStore) CreateApp(ctx context.Context, app *App) error {
	if app.ID == "" {
		app.ID = uuid.New().String()
	}
	now := time.Now().UTC()
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO apps (id, name, app_id, client_id, client_secret, private_key, base_url, is_default, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING created_at, updated_at
	`, app.ID, app.Name, app.AppID, app.ClientID, app.ClientSecret, app.PrivateKey, app.BaseURL, app.IsDefault, now, now,
	).Scan(&app.CreatedAt, &app.UpdatedAt)
	return err
}

func (s *PostgresStore) GetAppByID(ctx context.Context, id string) (*App, error) {
	a := &App{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, app_id, client_id, client_secret, private_key, base_url, is_default, created_at, updated_at FROM apps WHERE id = $1`, id,
	).Scan(&a.ID, &a.Name, &a.AppID, &a.ClientID, &a.ClientSecret, &a.PrivateKey, &a.BaseURL, &a.IsDefault, &a.CreatedAt, &a.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *PostgresStore) GetDefaultApp(ctx context.Context) (*App, error) {
	a := &App{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, app_id, client_id, client_secret, private_key, base_url, is_default, created_at, updated_at FROM apps WHERE is_default = TRUE LIMIT 1`,
	).Scan(&a.ID, &a.Name, &a.AppID, &a.ClientID, &a.ClientSecret, &a.PrivateKey, &a.BaseURL, &a.IsDefault, &a.CreatedAt, &a.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return a, nil
}

func (s *PostgresStore) ListApps(ctx context.Context) ([]*App, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, app_id, client_id, client_secret, private_key, base_url, is_default, created_at, updated_at FROM apps ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []*App
	for rows.Next() {
		a := &App{}
		if err := rows.Scan(&a.ID, &a.Name, &a.AppID, &a.ClientID, &a.ClientSecret, &a.PrivateKey, &a.BaseURL, &a.IsDefault, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		apps = append(apps, a)
	}
	return apps, rows.Err()
}

func (s *PostgresStore) UpdateApp(ctx context.Context, app *App) error {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `
		UPDATE apps SET name = $1, app_id = $2, client_id = $3, client_secret = $4, private_key = $5, base_url = $6, is_default = $7, updated_at = $8
		WHERE id = $9
	`, app.Name, app.AppID, app.ClientID, app.ClientSecret, app.PrivateKey, app.BaseURL, app.IsDefault, now, app.ID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("app %s: %w", app.ID, ErrNotFound)
	}
	app.UpdatedAt = now
	return nil
}

func (s *PostgresStore) DeleteApp(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM apps WHERE id = $1`, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("app %s: %w", id, ErrNotFound)
	}
	return nil
}

// Ensure PostgresStore implements all required interfaces.
var (
	_ Store             = (*PostgresStore)(nil)
	_ MigrationExecutor = (*PostgresStore)(nil)
)
