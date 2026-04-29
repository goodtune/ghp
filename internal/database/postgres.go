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
	err := s.db.QueryRowContext(ctx, `
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
		RETURNING id, created_at, updated_at
	`, token.ID, token.UserID, token.AppID, token.AccessToken, token.RefreshToken,
		token.AccessTokenExpiresAt, token.RefreshTokenExpiresAt,
		token.Scopes, now, now,
	).Scan(&token.ID, &token.CreatedAt, &token.UpdatedAt)
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
		INSERT INTO proxy_tokens (id, token_hash, token_prefix, token_type, app_id, user_id, github_token_id, installation_id, repositories, scopes, session_id, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
	`, token.ID, token.TokenHash, token.TokenPrefix, tokenType, token.AppID, token.UserID, token.GitHubTokenID,
		token.InstallationID, string(reposJSON), string(scopesJSON), token.SessionID,
		token.ExpiresAt, now)
	return err
}

func scanPostgresProxyToken(scan func(dest ...interface{}) error) (*ProxyToken, error) {
	t := &ProxyToken{}
	var scopesStr, reposStr string
	var expiresAt, revokedAt sql.NullTime
	var appID, userID, githubTokenID sql.NullString
	var installationID sql.NullInt64
	err := scan(&t.ID, &t.TokenHash, &t.TokenPrefix, &t.TokenType, &appID, &userID, &githubTokenID, &installationID, &reposStr, &scopesStr,
		&t.SessionID, &expiresAt, &revokedAt, &t.CreatedAt)
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
	if expiresAt.Valid {
		t.ExpiresAt = &expiresAt.Time
	}
	if revokedAt.Valid {
		t.RevokedAt = &revokedAt.Time
	}
	return t, nil
}

const pgProxyTokenCols = `id, token_hash, token_prefix, token_type, app_id, user_id, github_token_id, installation_id, repositories, scopes, session_id, expires_at, revoked_at, created_at`

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
		`SELECT `+pgProxyTokenCols+` FROM proxy_tokens WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY created_at DESC`)
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

func (s *PostgresStore) UpdateProxyTokenScopes(ctx context.Context, id string, repositories json.RawMessage, scopes json.RawMessage) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE proxy_tokens SET repositories = $1, scopes = $2 WHERE id = $3`,
		string(repositories), string(scopes), id)
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

func (s *PostgresStore) DeleteExpiredProxyTokens(ctx context.Context, olderThan time.Duration) (int64, error) {
	if olderThan <= 0 {
		return 0, fmt.Errorf("DeleteExpiredProxyTokens: olderThan must be positive, got %v", olderThan)
	}
	// The cutoff is computed with the application clock rather than the DB
	// clock so that all three backends (Postgres, SQLite, Vault) share
	// identical semantics. Vault has no DB-side NOW(), and the retention
	// window (default 30 days) dwarfs any realistic clock skew between
	// instances, so app-clock accuracy is sufficient here.
	cutoff := time.Now().UTC().Add(-olderThan)
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM proxy_tokens
		WHERE (revoked_at IS NOT NULL AND revoked_at < $1)
		   OR (expires_at IS NOT NULL AND expires_at < $1)
	`, cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
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

func (s *PostgresStore) SetDefaultApp(ctx context.Context, appID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Verify the target app exists.
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM apps WHERE id = $1`, appID).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return fmt.Errorf("app %s: %w", appID, ErrNotFound)
	}

	now := time.Now().UTC()

	// Clear default flag on all other apps.
	if _, err := tx.ExecContext(ctx,
		`UPDATE apps SET is_default = FALSE, updated_at = $1 WHERE is_default = TRUE AND id != $2`, now, appID,
	); err != nil {
		return err
	}

	// Set the target app as default.
	if _, err := tx.ExecContext(ctx,
		`UPDATE apps SET is_default = TRUE, updated_at = $1 WHERE id = $2`, now, appID,
	); err != nil {
		return err
	}

	return tx.Commit()
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

// --- Cached repositories ---

func (s *PostgresStore) CreateCachedRepository(ctx context.Context, repo *CachedRepository) error {
	if repo.ID == "" {
		repo.ID = uuid.New().String()
	}
	now := time.Now().UTC()
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO cached_repositories (id, owner, name, enabled, timeout_seconds, max_cache_size_mb, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING created_at, updated_at
	`, repo.ID, repo.Owner, repo.Name, repo.Enabled, repo.TimeoutSeconds, repo.MaxCacheSizeMB, now, now,
	).Scan(&repo.CreatedAt, &repo.UpdatedAt)
	return err
}

func (s *PostgresStore) GetCachedRepositoryByID(ctx context.Context, id string) (*CachedRepository, error) {
	r := &CachedRepository{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, owner, name, enabled, timeout_seconds, max_cache_size_mb, created_at, updated_at FROM cached_repositories WHERE id = $1`, id,
	).Scan(&r.ID, &r.Owner, &r.Name, &r.Enabled, &r.TimeoutSeconds, &r.MaxCacheSizeMB, &r.CreatedAt, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *PostgresStore) GetCachedRepositoryByOwnerName(ctx context.Context, owner, name string) (*CachedRepository, error) {
	r := &CachedRepository{}
	err := s.db.QueryRowContext(ctx,
		`SELECT id, owner, name, enabled, timeout_seconds, max_cache_size_mb, created_at, updated_at FROM cached_repositories WHERE owner = $1 AND name = $2`, owner, name,
	).Scan(&r.ID, &r.Owner, &r.Name, &r.Enabled, &r.TimeoutSeconds, &r.MaxCacheSizeMB, &r.CreatedAt, &r.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *PostgresStore) ListCachedRepositories(ctx context.Context) ([]*CachedRepository, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, owner, name, enabled, timeout_seconds, max_cache_size_mb, created_at, updated_at FROM cached_repositories ORDER BY owner, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var repos []*CachedRepository
	for rows.Next() {
		r := &CachedRepository{}
		if err := rows.Scan(&r.ID, &r.Owner, &r.Name, &r.Enabled, &r.TimeoutSeconds, &r.MaxCacheSizeMB, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		repos = append(repos, r)
	}
	return repos, rows.Err()
}

func (s *PostgresStore) UpdateCachedRepository(ctx context.Context, repo *CachedRepository) error {
	now := time.Now().UTC()
	result, err := s.db.ExecContext(ctx, `
		UPDATE cached_repositories SET owner = $1, name = $2, enabled = $3, timeout_seconds = $4, max_cache_size_mb = $5, updated_at = $6
		WHERE id = $7
	`, repo.Owner, repo.Name, repo.Enabled, repo.TimeoutSeconds, repo.MaxCacheSizeMB, now, repo.ID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("cached repository %s: %w", repo.ID, ErrNotFound)
	}
	repo.UpdatedAt = now
	return nil
}

func (s *PostgresStore) DeleteCachedRepository(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM cached_repositories WHERE id = $1`, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("cached repository %s: %w", id, ErrNotFound)
	}
	return nil
}

// --- Sessions ---

func (s *PostgresStore) CreateSession(ctx context.Context, sess *Session) error {
	if sess.TokenHash == "" {
		return fmt.Errorf("CreateSession: TokenHash required")
	}
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (token_hash, user_id, username, role, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, sess.TokenHash, sess.UserID, sess.Username, sess.Role, sess.ExpiresAt.UTC(), sess.CreatedAt.UTC())
	return err
}

func (s *PostgresStore) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT token_hash, user_id, username, role, expires_at, created_at
		FROM sessions WHERE token_hash = $1
	`, tokenHash)
	sess := &Session{}
	err := row.Scan(&sess.TokenHash, &sess.UserID, &sess.Username, &sess.Role, &sess.ExpiresAt, &sess.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session: %w", ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	if !sess.ExpiresAt.IsZero() && time.Now().After(sess.ExpiresAt) {
		return nil, fmt.Errorf("session: %w", ErrNotFound)
	}
	return sess, nil
}

func (s *PostgresStore) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = $1`, tokenHash)
	return err
}

func (s *PostgresStore) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	cutoff := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- OAuth states ---

func (s *PostgresStore) CreateOAuthState(ctx context.Context, st *OAuthState) error {
	if st.State == "" {
		return fmt.Errorf("CreateOAuthState: State required")
	}
	if st.Kind != OAuthStateKindLogin && st.Kind != OAuthStateKindBroker {
		return fmt.Errorf("CreateOAuthState: invalid Kind %q", st.Kind)
	}
	if st.CreatedAt.IsZero() {
		st.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oauth_states (state, kind, return_to, broker_redirect_uri, broker_downstream_state, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, st.State, st.Kind, st.ReturnTo, st.BrokerRedirectURI, st.BrokerDownstreamState,
		st.ExpiresAt.UTC(), st.CreatedAt.UTC())
	return err
}

func (s *PostgresStore) ConsumeOAuthState(ctx context.Context, state, kind string) (*OAuthState, error) {
	// DELETE ... RETURNING is atomic — exactly the read-and-delete semantics
	// we need so a state token can never be replayed by a duplicate callback.
	row := s.db.QueryRowContext(ctx, `
		DELETE FROM oauth_states WHERE state = $1 AND kind = $2
		RETURNING state, kind, return_to, broker_redirect_uri, broker_downstream_state, expires_at, created_at
	`, state, kind)
	st := &OAuthState{}
	err := row.Scan(&st.State, &st.Kind, &st.ReturnTo, &st.BrokerRedirectURI, &st.BrokerDownstreamState, &st.ExpiresAt, &st.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("oauth_state: %w", ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	if !st.ExpiresAt.IsZero() && time.Now().After(st.ExpiresAt) {
		return nil, fmt.Errorf("oauth_state: %w", ErrNotFound)
	}
	return st, nil
}

func (s *PostgresStore) DeleteExpiredOAuthStates(ctx context.Context) (int64, error) {
	cutoff := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `DELETE FROM oauth_states WHERE expires_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- Device authorization ---

func (s *PostgresStore) CreateDeviceAuth(ctx context.Context, da *DeviceAuth) error {
	if da.DeviceCode == "" || da.UserCode == "" {
		return fmt.Errorf("CreateDeviceAuth: DeviceCode and UserCode required")
	}
	if da.Status == "" {
		da.Status = DeviceAuthStatusPending
	}
	if da.CreatedAt.IsZero() {
		da.CreatedAt = time.Now().UTC()
	}
	var lastPolled interface{}
	if da.LastPolledAt != nil {
		lastPolled = da.LastPolledAt.UTC()
	}
	var sessTok, username interface{}
	if da.SessionToken != "" {
		sessTok = da.SessionToken
	}
	if da.Username != "" {
		username = da.Username
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cli_device_authorizations
			(device_code, user_code, status, session_token, username, last_polled_at, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, da.DeviceCode, da.UserCode, da.Status, sessTok, username, lastPolled,
		da.ExpiresAt.UTC(), da.CreatedAt.UTC())
	return err
}

func (s *PostgresStore) GetDeviceAuthByDeviceCode(ctx context.Context, deviceCode string) (*DeviceAuth, error) {
	return s.scanDeviceAuth(ctx, `
		SELECT device_code, user_code, status, session_token, username, last_polled_at, expires_at, created_at
		FROM cli_device_authorizations WHERE device_code = $1
	`, deviceCode)
}

func (s *PostgresStore) GetDeviceAuthByUserCode(ctx context.Context, userCode string) (*DeviceAuth, error) {
	return s.scanDeviceAuth(ctx, `
		SELECT device_code, user_code, status, session_token, username, last_polled_at, expires_at, created_at
		FROM cli_device_authorizations WHERE user_code = $1
	`, userCode)
}

func (s *PostgresStore) scanDeviceAuth(ctx context.Context, query, arg string) (*DeviceAuth, error) {
	row := s.db.QueryRowContext(ctx, query, arg)
	da := &DeviceAuth{}
	var sessTok, username sql.NullString
	var lastPolled sql.NullTime
	err := row.Scan(&da.DeviceCode, &da.UserCode, &da.Status, &sessTok, &username, &lastPolled, &da.ExpiresAt, &da.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("device_auth: %w", ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	if sessTok.Valid {
		da.SessionToken = sessTok.String
	}
	if username.Valid {
		da.Username = username.String
	}
	if lastPolled.Valid {
		t := lastPolled.Time
		da.LastPolledAt = &t
	}
	if !da.ExpiresAt.IsZero() && time.Now().After(da.ExpiresAt) {
		return nil, fmt.Errorf("device_auth: %w", ErrNotFound)
	}
	return da, nil
}

func (s *PostgresStore) UpdateDeviceAuth(ctx context.Context, da *DeviceAuth) error {
	var lastPolled interface{}
	if da.LastPolledAt != nil {
		lastPolled = da.LastPolledAt.UTC()
	}
	var sessTok, username interface{}
	if da.SessionToken != "" {
		sessTok = da.SessionToken
	}
	if da.Username != "" {
		username = da.Username
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE cli_device_authorizations
		SET status = $1, session_token = $2, username = $3, last_polled_at = $4, expires_at = $5
		WHERE device_code = $6
	`, da.Status, sessTok, username, lastPolled, da.ExpiresAt.UTC(), da.DeviceCode)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("device_auth %s: %w", da.DeviceCode, ErrNotFound)
	}
	return nil
}

func (s *PostgresStore) DeleteDeviceAuth(ctx context.Context, deviceCode string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM cli_device_authorizations WHERE device_code = $1`, deviceCode)
	return err
}

func (s *PostgresStore) DeleteExpiredDeviceAuths(ctx context.Context) (int64, error) {
	cutoff := time.Now().UTC()
	res, err := s.db.ExecContext(ctx, `DELETE FROM cli_device_authorizations WHERE expires_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Ensure PostgresStore implements all required interfaces.
var (
	_ Store             = (*PostgresStore)(nil)
	_ MigrationExecutor = (*PostgresStore)(nil)
)
