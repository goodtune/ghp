package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// SQLiteStore implements Store using SQLite.
type SQLiteStore struct {
	db *sql.DB
}

// NewSQLiteStore opens a SQLite database at the given path.
func NewSQLiteStore(dsn string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite: %w", err)
	}

	// Enable WAL mode and foreign keys.
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("setting pragma %s: %w", pragma, err)
		}
	}

	return &SQLiteStore{db: db}, nil
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}

// parseTime parses a time string from SQLite. Handles RFC3339, RFC3339Nano,
// and the format SQLite's strftime produces.
func parseTime(s string) time.Time {
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// --- Migration support ---

func (s *SQLiteStore) EnsureMigrationsTable(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			name TEXT PRIMARY KEY,
			applied_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
		)
	`)
	return err
}

func (s *SQLiteStore) AppliedMigrations(ctx context.Context) ([]string, error) {
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

func (s *SQLiteStore) RunMigration(ctx context.Context, name, sqlStr string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, sqlStr); err != nil {
		return fmt.Errorf("executing migration SQL: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `INSERT INTO schema_migrations (name) VALUES (?)`, name); err != nil {
		return fmt.Errorf("recording migration: %w", err)
	}

	return tx.Commit()
}

// --- Users ---

func (s *SQLiteStore) UpsertUser(ctx context.Context, user *User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, github_id, github_username, github_email, role, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(github_id) DO UPDATE SET
			github_username = excluded.github_username,
			github_email = excluded.github_email,
			updated_at = excluded.updated_at
	`, user.ID, user.GitHubID, user.GitHubUsername, user.GitHubEmail, user.Role, now, now)
	if err != nil {
		return err
	}
	// Re-read to get the actual ID (in case of conflict, the existing row's ID is used).
	var createdStr, updatedStr string
	err = s.db.QueryRowContext(ctx,
		`SELECT id, role, created_at, updated_at FROM users WHERE github_id = ?`, user.GitHubID,
	).Scan(&user.ID, &user.Role, &createdStr, &updatedStr)
	if err != nil {
		return err
	}
	user.CreatedAt = parseTime(createdStr)
	user.UpdatedAt = parseTime(updatedStr)
	return nil
}

func (s *SQLiteStore) GetUserByGitHubID(ctx context.Context, githubID int64) (*User, error) {
	u := &User{}
	var createdStr, updatedStr string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, github_id, github_username, github_email, role, created_at, updated_at FROM users WHERE github_id = ?`,
		githubID,
	).Scan(&u.ID, &u.GitHubID, &u.GitHubUsername, &u.GitHubEmail, &u.Role, &createdStr, &updatedStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt = parseTime(createdStr)
	u.UpdatedAt = parseTime(updatedStr)
	return u, nil
}

func (s *SQLiteStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	u := &User{}
	var createdStr, updatedStr string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, github_id, github_username, github_email, role, created_at, updated_at FROM users WHERE id = ?`,
		id,
	).Scan(&u.ID, &u.GitHubID, &u.GitHubUsername, &u.GitHubEmail, &u.Role, &createdStr, &updatedStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u.CreatedAt = parseTime(createdStr)
	u.UpdatedAt = parseTime(updatedStr)
	return u, nil
}

func (s *SQLiteStore) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, github_id, github_username, github_email, role, created_at, updated_at FROM users ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		u := &User{}
		var createdStr, updatedStr string
		if err := rows.Scan(&u.ID, &u.GitHubID, &u.GitHubUsername, &u.GitHubEmail, &u.Role, &createdStr, &updatedStr); err != nil {
			return nil, err
		}
		u.CreatedAt = parseTime(createdStr)
		u.UpdatedAt = parseTime(updatedStr)
		users = append(users, u)
	}
	return users, rows.Err()
}

// --- GitHub Tokens ---

func (s *SQLiteStore) UpsertGitHubToken(ctx context.Context, token *GitHubToken) error {
	if token.ID == "" {
		token.ID = uuid.New().String()
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO github_tokens (id, user_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at, scopes, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			access_token = excluded.access_token,
			refresh_token = excluded.refresh_token,
			access_token_expires_at = excluded.access_token_expires_at,
			refresh_token_expires_at = excluded.refresh_token_expires_at,
			scopes = excluded.scopes,
			updated_at = excluded.updated_at
	`, token.ID, token.UserID, token.AccessToken, token.RefreshToken,
		token.AccessTokenExpiresAt.Format(time.RFC3339Nano),
		token.RefreshTokenExpiresAt.Format(time.RFC3339Nano),
		token.Scopes, now, now)
	return err
}

func (s *SQLiteStore) GetGitHubToken(ctx context.Context, userID string) (*GitHubToken, error) {
	t := &GitHubToken{}
	var atExp, rtExp, createdStr, updatedStr string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at, scopes, created_at, updated_at
		 FROM github_tokens WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1`, userID,
	).Scan(&t.ID, &t.UserID, &t.AccessToken, &t.RefreshToken, &atExp, &rtExp, &t.Scopes, &createdStr, &updatedStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.AccessTokenExpiresAt = parseTime(atExp)
	t.RefreshTokenExpiresAt = parseTime(rtExp)
	t.CreatedAt = parseTime(createdStr)
	t.UpdatedAt = parseTime(updatedStr)
	return t, nil
}

func (s *SQLiteStore) GetGitHubTokenByID(ctx context.Context, id string) (*GitHubToken, error) {
	t := &GitHubToken{}
	var atExp, rtExp, createdStr, updatedStr string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at, scopes, created_at, updated_at
		 FROM github_tokens WHERE id = ?`, id,
	).Scan(&t.ID, &t.UserID, &t.AccessToken, &t.RefreshToken, &atExp, &rtExp, &t.Scopes, &createdStr, &updatedStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	t.AccessTokenExpiresAt = parseTime(atExp)
	t.RefreshTokenExpiresAt = parseTime(rtExp)
	t.CreatedAt = parseTime(createdStr)
	t.UpdatedAt = parseTime(updatedStr)
	return t, nil
}

// --- Proxy Tokens ---

func (s *SQLiteStore) CreateProxyToken(ctx context.Context, token *ProxyToken) error {
	if token.ID == "" {
		token.ID = uuid.New().String()
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	scopesJSON, err := json.Marshal(token.Scopes)
	if err != nil {
		return fmt.Errorf("marshaling scopes: %w", err)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO proxy_tokens (id, token_hash, token_prefix, user_id, github_token_id, repository, scopes, session_id, expires_at, request_count, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
	`, token.ID, token.TokenHash, token.TokenPrefix, token.UserID, token.GitHubTokenID,
		token.Repository, string(scopesJSON), token.SessionID,
		token.ExpiresAt.Format(time.RFC3339Nano), now)
	return err
}

func scanProxyToken(scan func(dest ...interface{}) error) (*ProxyToken, error) {
	t := &ProxyToken{}
	var scopesStr string
	var revokedAt, lastUsedAt sql.NullString
	var expiresStr, createdStr string
	err := scan(&t.ID, &t.TokenHash, &t.TokenPrefix, &t.UserID, &t.GitHubTokenID, &t.Repository, &scopesStr,
		&t.SessionID, &expiresStr, &revokedAt, &lastUsedAt, &t.RequestCount, &createdStr)
	if err != nil {
		return nil, err
	}
	t.Scopes = json.RawMessage(scopesStr)
	t.ExpiresAt = parseTime(expiresStr)
	t.CreatedAt = parseTime(createdStr)
	if revokedAt.Valid {
		ts := parseTime(revokedAt.String)
		t.RevokedAt = &ts
	}
	if lastUsedAt.Valid {
		ts := parseTime(lastUsedAt.String)
		t.LastUsedAt = &ts
	}
	return t, nil
}

func (s *SQLiteStore) GetProxyTokenByHash(ctx context.Context, hash string) (*ProxyToken, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, token_hash, token_prefix, user_id, github_token_id, repository, scopes, session_id, expires_at, revoked_at, last_used_at, request_count, created_at
		FROM proxy_tokens WHERE token_hash = ?`, hash)
	t, err := scanProxyToken(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

func (s *SQLiteStore) GetProxyTokenByID(ctx context.Context, id string) (*ProxyToken, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, token_hash, token_prefix, user_id, github_token_id, repository, scopes, session_id, expires_at, revoked_at, last_used_at, request_count, created_at
		FROM proxy_tokens WHERE id = ?`, id)
	t, err := scanProxyToken(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

func (s *SQLiteStore) ListProxyTokens(ctx context.Context, userID string) ([]*ProxyToken, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, token_hash, token_prefix, user_id, github_token_id, repository, scopes, session_id, expires_at, revoked_at, last_used_at, request_count, created_at
		FROM proxy_tokens WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProxyTokenRows(rows)
}

func (s *SQLiteStore) ListAllProxyTokens(ctx context.Context) ([]*ProxyToken, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, token_hash, token_prefix, user_id, github_token_id, repository, scopes, session_id, expires_at, revoked_at, last_used_at, request_count, created_at
		FROM proxy_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProxyTokenRows(rows)
}

func scanProxyTokenRows(rows *sql.Rows) ([]*ProxyToken, error) {
	var tokens []*ProxyToken
	for rows.Next() {
		t, err := scanProxyToken(rows.Scan)
		if err != nil {
			return nil, err
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

func (s *SQLiteStore) RevokeProxyToken(ctx context.Context, id string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `UPDATE proxy_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`, now, id)
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

func (s *SQLiteStore) UpdateProxyTokenUsage(ctx context.Context, id string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx,
		`UPDATE proxy_tokens SET last_used_at = ?, request_count = request_count + 1 WHERE id = ?`, now, id)
	return err
}

// --- Audit Log ---

func (s *SQLiteStore) CreateAuditEntry(ctx context.Context, entry *AuditEntry) error {
	if entry.ID == "" {
		entry.ID = uuid.New().String()
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	metadataStr := "{}"
	if entry.Metadata != nil {
		metadataStr = string(entry.Metadata)
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_log (id, timestamp, user_id, proxy_token_id, action, method, path, repository, status_code, duration_ms, session_id, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, entry.ID, now, entry.UserID, entry.ProxyTokenID, entry.Action, entry.Method, entry.Path,
		entry.Repository, entry.StatusCode, entry.DurationMS, entry.SessionID, metadataStr)
	return err
}

func (s *SQLiteStore) ListAuditEntries(ctx context.Context, filter AuditFilter) ([]*AuditEntry, error) {
	query := `SELECT id, timestamp, user_id, proxy_token_id, action, method, path, repository, status_code, duration_ms, session_id, metadata FROM audit_log WHERE 1=1`
	var args []interface{}

	if filter.UserID != "" {
		query += ` AND user_id = ?`
		args = append(args, filter.UserID)
	}
	if filter.Repository != "" {
		query += ` AND repository = ?`
		args = append(args, filter.Repository)
	}
	if filter.TokenID != "" {
		query += ` AND proxy_token_id = ?`
		args = append(args, filter.TokenID)
	}
	if filter.Action != "" {
		query += ` AND action = ?`
		args = append(args, filter.Action)
	}
	if filter.StatusCode != 0 {
		query += ` AND status_code = ?`
		args = append(args, filter.StatusCode)
	}

	query += ` ORDER BY timestamp DESC`

	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	query += fmt.Sprintf(` LIMIT %d`, limit)
	if filter.Offset > 0 {
		query += fmt.Sprintf(` OFFSET %d`, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []*AuditEntry
	for rows.Next() {
		e := &AuditEntry{}
		var proxyTokenID sql.NullString
		var metadataStr sql.NullString
		var timestampStr string
		if err := rows.Scan(&e.ID, &timestampStr, &e.UserID, &proxyTokenID, &e.Action, &e.Method,
			&e.Path, &e.Repository, &e.StatusCode, &e.DurationMS, &e.SessionID, &metadataStr); err != nil {
			return nil, err
		}
		e.Timestamp = parseTime(timestampStr)
		if proxyTokenID.Valid {
			e.ProxyTokenID = &proxyTokenID.String
		}
		if metadataStr.Valid {
			e.Metadata = json.RawMessage(metadataStr.String)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Ensure SQLiteStore implements all required interfaces.
var (
	_ Store             = (*SQLiteStore)(nil)
	_ MigrationExecutor = (*SQLiteStore)(nil)
)
