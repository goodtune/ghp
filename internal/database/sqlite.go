package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
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
	// Check for in-memory databases before modifying the DSN.
	inMemory := dsn == ":memory:" || dsn == "file::memory:"

	// Append _pragma DSN parameters so that every connection created by the
	// pool inherits these settings. Setting PRAGMAs via db.Exec() only
	// affects the single connection that runs the statement; under concurrent
	// load the pool creates additional connections that would miss them.
	dsn = appendSQLitePragmas(dsn)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite: %w", err)
	}

	// In-memory databases are per-connection, so restrict the pool to a
	// single connection to ensure all operations share the same database.
	if inMemory {
		db.SetMaxOpenConns(1)
	}

	return &SQLiteStore{db: db}, nil
}

// appendSQLitePragmas adds _pragma query parameters to the DSN so that
// modernc.org/sqlite applies them on every new connection. If the DSN
// already contains a query string the parameters are appended; otherwise
// a new query string is started.
//
// The bare ":memory:" shorthand is normalised to "file::memory:" (URI form)
// before appending parameters, because ":memory:?key=val" is not recognised
// as an in-memory database by SQLite — it would be treated as a literal
// filename.
func appendSQLitePragmas(dsn string) string {
	if dsn == ":memory:" {
		dsn = "file::memory:"
	}
	pragmas := "_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)"
	if strings.Contains(dsn, "?") {
		return dsn + "&" + pragmas
	}
	return dsn + "?" + pragmas
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

// sqliteAuthTimestampLayout is the fixed-width, millisecond-precision
// timestamp layout used for auth-state rows (sessions, oauth_states,
// cli_device_authorizations). Two reasons to prefer it over RFC3339Nano:
//
//   - It always emits exactly 3 fractional digits, so lexicographic
//     comparison agrees with chronological order. RFC3339Nano omits
//     trailing zeros ("...:05Z" vs "...:05.123Z"), which would flip
//     ordering at second boundaries in the cleanup DELETEs.
//   - It matches the migration's own default expression
//     (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) so DB-defaulted and
//     application-written values share one format.
//
// We deliberately do NOT change the timestamp format for older tables
// (proxy_tokens etc.); their cleanup logic is unaffected and rewriting
// existing values is out of scope for this PR.
const sqliteAuthTimestampLayout = "2006-01-02T15:04:05.000Z"

func sqliteFmtAuthTime(t time.Time) string {
	return t.UTC().Format(sqliteAuthTimestampLayout)
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
			role = excluded.role,
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

func (s *SQLiteStore) SyncAdminRoles(ctx context.Context, adminUsernames []string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now().UTC().Format(time.RFC3339Nano)

	// Demote all current admins to 'user'.
	if _, err := tx.ExecContext(ctx,
		`UPDATE users SET role = 'user', updated_at = ? WHERE role = 'admin'`, now,
	); err != nil {
		return err
	}

	// Promote the configured admins.
	for _, username := range adminUsernames {
		if _, err := tx.ExecContext(ctx,
			`UPDATE users SET role = 'admin', updated_at = ? WHERE LOWER(github_username) = LOWER(?)`,
			now, username,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
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
		INSERT INTO github_tokens (id, user_id, app_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at, scopes, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
			access_token = excluded.access_token,
			refresh_token = excluded.refresh_token,
			access_token_expires_at = excluded.access_token_expires_at,
			refresh_token_expires_at = excluded.refresh_token_expires_at,
			scopes = excluded.scopes,
			app_id = excluded.app_id,
			updated_at = excluded.updated_at
	`, token.ID, token.UserID, token.AppID, token.AccessToken, token.RefreshToken,
		token.AccessTokenExpiresAt.Format(time.RFC3339Nano),
		token.RefreshTokenExpiresAt.Format(time.RFC3339Nano),
		token.Scopes, now, now)
	if err != nil {
		return err
	}
	// Re-read to get the actual ID and timestamps (on conflict, the existing row's ID is kept).
	var createdStr, updatedStr string
	err = s.db.QueryRowContext(ctx,
		`SELECT id, created_at, updated_at FROM github_tokens WHERE user_id = ?`, token.UserID,
	).Scan(&token.ID, &createdStr, &updatedStr)
	if err != nil {
		return err
	}
	token.CreatedAt = parseTime(createdStr)
	token.UpdatedAt = parseTime(updatedStr)
	return nil
}

func (s *SQLiteStore) GetGitHubToken(ctx context.Context, userID string) (*GitHubToken, error) {
	t := &GitHubToken{}
	var atExp, rtExp, createdStr, updatedStr string
	var appID sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, app_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at, scopes, created_at, updated_at
		 FROM github_tokens WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1`, userID,
	).Scan(&t.ID, &t.UserID, &appID, &t.AccessToken, &t.RefreshToken, &atExp, &rtExp, &t.Scopes, &createdStr, &updatedStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if appID.Valid {
		t.AppID = &appID.String
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
	var appID sql.NullString
	err := s.db.QueryRowContext(ctx,
		`SELECT id, user_id, app_id, access_token, refresh_token, access_token_expires_at, refresh_token_expires_at, scopes, created_at, updated_at
		 FROM github_tokens WHERE id = ?`, id,
	).Scan(&t.ID, &t.UserID, &appID, &t.AccessToken, &t.RefreshToken, &atExp, &rtExp, &t.Scopes, &createdStr, &updatedStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if appID.Valid {
		t.AppID = &appID.String
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
	reposJSON, err := json.Marshal(token.Repositories)
	if err != nil {
		return fmt.Errorf("marshaling repositories: %w", err)
	}
	tokenType := token.TokenType
	if tokenType == "" {
		tokenType = DefaultTokenType
	}
	var expiresAtStr interface{}
	if token.ExpiresAt != nil {
		expiresAtStr = token.ExpiresAt.Format(time.RFC3339Nano)
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO proxy_tokens (id, token_hash, token_prefix, token_type, app_id, user_id, github_token_id, installation_id, repositories, scopes, session_id, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, token.ID, token.TokenHash, token.TokenPrefix, tokenType, token.AppID, token.UserID, token.GitHubTokenID,
		token.InstallationID, string(reposJSON), string(scopesJSON), token.SessionID,
		expiresAtStr, now)
	return err
}

func scanProxyToken(scan func(dest ...interface{}) error) (*ProxyToken, error) {
	t := &ProxyToken{}
	var scopesStr, reposStr string
	var revokedAt, expiresAt sql.NullString
	var createdStr string
	var appID, userID, githubTokenID sql.NullString
	var installationID sql.NullInt64
	err := scan(&t.ID, &t.TokenHash, &t.TokenPrefix, &t.TokenType, &appID, &userID, &githubTokenID, &installationID, &reposStr, &scopesStr,
		&t.SessionID, &expiresAt, &revokedAt, &createdStr)
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
		ts := parseTime(expiresAt.String)
		t.ExpiresAt = &ts
	}
	t.CreatedAt = parseTime(createdStr)
	if revokedAt.Valid {
		ts := parseTime(revokedAt.String)
		t.RevokedAt = &ts
	}
	return t, nil
}

func (s *SQLiteStore) GetProxyTokenByHash(ctx context.Context, hash string) (*ProxyToken, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, token_hash, token_prefix, token_type, app_id, user_id, github_token_id, installation_id, repositories, scopes, session_id, expires_at, revoked_at, created_at
		FROM proxy_tokens WHERE token_hash = ?`, hash)
	t, err := scanProxyToken(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

func (s *SQLiteStore) GetProxyTokenByID(ctx context.Context, id string) (*ProxyToken, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, token_hash, token_prefix, token_type, app_id, user_id, github_token_id, installation_id, repositories, scopes, session_id, expires_at, revoked_at, created_at
		FROM proxy_tokens WHERE id = ?`, id)
	t, err := scanProxyToken(row.Scan)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return t, err
}

func (s *SQLiteStore) ListProxyTokens(ctx context.Context, userID string) ([]*ProxyToken, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, token_hash, token_prefix, token_type, app_id, user_id, github_token_id, installation_id, repositories, scopes, session_id, expires_at, revoked_at, created_at
		FROM proxy_tokens WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProxyTokenRows(rows)
}

func (s *SQLiteStore) ListAllProxyTokens(ctx context.Context) ([]*ProxyToken, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, token_hash, token_prefix, token_type, app_id, user_id, github_token_id, installation_id, repositories, scopes, session_id, expires_at, revoked_at, created_at
		FROM proxy_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanProxyTokenRows(rows)
}

func (s *SQLiteStore) ListActiveProxyTokens(ctx context.Context) ([]*ProxyToken, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, token_hash, token_prefix, token_type, app_id, user_id, github_token_id, installation_id, repositories, scopes, session_id, expires_at, revoked_at, created_at
		FROM proxy_tokens WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?) ORDER BY created_at DESC`,
		time.Now().UTC().Format(time.RFC3339Nano))
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

func (s *SQLiteStore) UpdateProxyTokenAppID(ctx context.Context, id string, appID string) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE proxy_tokens SET app_id = ? WHERE id = ?`, appID, id)
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

func (s *SQLiteStore) UpdateProxyTokenScopes(ctx context.Context, id string, repositories json.RawMessage, scopes json.RawMessage) error {
	result, err := s.db.ExecContext(ctx,
		`UPDATE proxy_tokens SET repositories = ?, scopes = ? WHERE id = ?`,
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

func (s *SQLiteStore) DeleteExpiredProxyTokens(ctx context.Context, olderThan time.Duration) (int64, error) {
	if olderThan <= 0 {
		return 0, fmt.Errorf("DeleteExpiredProxyTokens: olderThan must be positive, got %v", olderThan)
	}
	// See PostgresStore.DeleteExpiredProxyTokens for why the cutoff is
	// computed with the application clock instead of a DB-side NOW().
	cutoff := time.Now().UTC().Add(-olderThan).Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `
		DELETE FROM proxy_tokens
		WHERE (revoked_at IS NOT NULL AND revoked_at < ?)
		   OR (expires_at IS NOT NULL AND expires_at < ?)
	`, cutoff, cutoff)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// --- Apps ---

func (s *SQLiteStore) CreateApp(ctx context.Context, app *App) error {
	if app.ID == "" {
		app.ID = uuid.New().String()
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO apps (id, name, app_id, client_id, client_secret, private_key, base_url, is_default, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, app.ID, app.Name, app.AppID, app.ClientID, app.ClientSecret, app.PrivateKey, app.BaseURL, app.IsDefault, now, now)
	if err != nil {
		return err
	}
	app.CreatedAt = parseTime(now)
	app.UpdatedAt = parseTime(now)
	return nil
}

func (s *SQLiteStore) GetAppByID(ctx context.Context, id string) (*App, error) {
	a := &App{}
	var createdStr, updatedStr string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, app_id, client_id, client_secret, private_key, base_url, is_default, created_at, updated_at FROM apps WHERE id = ?`, id,
	).Scan(&a.ID, &a.Name, &a.AppID, &a.ClientID, &a.ClientSecret, &a.PrivateKey, &a.BaseURL, &a.IsDefault, &createdStr, &updatedStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.CreatedAt = parseTime(createdStr)
	a.UpdatedAt = parseTime(updatedStr)
	return a, nil
}

func (s *SQLiteStore) GetDefaultApp(ctx context.Context) (*App, error) {
	a := &App{}
	var createdStr, updatedStr string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, app_id, client_id, client_secret, private_key, base_url, is_default, created_at, updated_at FROM apps WHERE is_default = 1 LIMIT 1`,
	).Scan(&a.ID, &a.Name, &a.AppID, &a.ClientID, &a.ClientSecret, &a.PrivateKey, &a.BaseURL, &a.IsDefault, &createdStr, &updatedStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.CreatedAt = parseTime(createdStr)
	a.UpdatedAt = parseTime(updatedStr)
	return a, nil
}

func (s *SQLiteStore) ListApps(ctx context.Context) ([]*App, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, app_id, client_id, client_secret, private_key, base_url, is_default, created_at, updated_at FROM apps ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var apps []*App
	for rows.Next() {
		a := &App{}
		var createdStr, updatedStr string
		if err := rows.Scan(&a.ID, &a.Name, &a.AppID, &a.ClientID, &a.ClientSecret, &a.PrivateKey, &a.BaseURL, &a.IsDefault, &createdStr, &updatedStr); err != nil {
			return nil, err
		}
		a.CreatedAt = parseTime(createdStr)
		a.UpdatedAt = parseTime(updatedStr)
		apps = append(apps, a)
	}
	return apps, rows.Err()
}

func (s *SQLiteStore) UpdateApp(ctx context.Context, app *App) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `
		UPDATE apps SET name = ?, app_id = ?, client_id = ?, client_secret = ?, private_key = ?, base_url = ?, is_default = ?, updated_at = ?
		WHERE id = ?
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
	app.UpdatedAt = parseTime(now)
	return nil
}

func (s *SQLiteStore) SetDefaultApp(ctx context.Context, appID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Verify the target app exists.
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM apps WHERE id = ?`, appID).Scan(&exists); err != nil {
		return err
	}
	if exists == 0 {
		return fmt.Errorf("app %s: %w", appID, ErrNotFound)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)

	// Clear default flag on all other apps.
	if _, err := tx.ExecContext(ctx,
		`UPDATE apps SET is_default = 0, updated_at = ? WHERE is_default = 1 AND id != ?`, now, appID,
	); err != nil {
		return err
	}

	// Set the target app as default.
	if _, err := tx.ExecContext(ctx,
		`UPDATE apps SET is_default = 1, updated_at = ? WHERE id = ?`, now, appID,
	); err != nil {
		return err
	}

	return tx.Commit()
}

func (s *SQLiteStore) DeleteApp(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM apps WHERE id = ?`, id)
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

func (s *SQLiteStore) CreateCachedRepository(ctx context.Context, repo *CachedRepository) error {
	if repo.ID == "" {
		repo.ID = uuid.New().String()
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO cached_repositories (id, owner, name, enabled, timeout_seconds, max_cache_size_mb, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, repo.ID, repo.Owner, repo.Name, repo.Enabled, repo.TimeoutSeconds, repo.MaxCacheSizeMB, now, now)
	if err != nil {
		return err
	}
	repo.CreatedAt = parseTime(now)
	repo.UpdatedAt = parseTime(now)
	return nil
}

func (s *SQLiteStore) GetCachedRepositoryByID(ctx context.Context, id string) (*CachedRepository, error) {
	r := &CachedRepository{}
	var createdStr, updatedStr string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, owner, name, enabled, timeout_seconds, max_cache_size_mb, created_at, updated_at FROM cached_repositories WHERE id = ?`, id,
	).Scan(&r.ID, &r.Owner, &r.Name, &r.Enabled, &r.TimeoutSeconds, &r.MaxCacheSizeMB, &createdStr, &updatedStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.CreatedAt = parseTime(createdStr)
	r.UpdatedAt = parseTime(updatedStr)
	return r, nil
}

func (s *SQLiteStore) GetCachedRepositoryByOwnerName(ctx context.Context, owner, name string) (*CachedRepository, error) {
	r := &CachedRepository{}
	var createdStr, updatedStr string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, owner, name, enabled, timeout_seconds, max_cache_size_mb, created_at, updated_at FROM cached_repositories WHERE owner = ? AND name = ?`, owner, name,
	).Scan(&r.ID, &r.Owner, &r.Name, &r.Enabled, &r.TimeoutSeconds, &r.MaxCacheSizeMB, &createdStr, &updatedStr)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.CreatedAt = parseTime(createdStr)
	r.UpdatedAt = parseTime(updatedStr)
	return r, nil
}

func (s *SQLiteStore) ListCachedRepositories(ctx context.Context) ([]*CachedRepository, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, owner, name, enabled, timeout_seconds, max_cache_size_mb, created_at, updated_at FROM cached_repositories ORDER BY owner, name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var repos []*CachedRepository
	for rows.Next() {
		r := &CachedRepository{}
		var createdStr, updatedStr string
		if err := rows.Scan(&r.ID, &r.Owner, &r.Name, &r.Enabled, &r.TimeoutSeconds, &r.MaxCacheSizeMB, &createdStr, &updatedStr); err != nil {
			return nil, err
		}
		r.CreatedAt = parseTime(createdStr)
		r.UpdatedAt = parseTime(updatedStr)
		repos = append(repos, r)
	}
	return repos, rows.Err()
}

func (s *SQLiteStore) UpdateCachedRepository(ctx context.Context, repo *CachedRepository) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	result, err := s.db.ExecContext(ctx, `
		UPDATE cached_repositories SET owner = ?, name = ?, enabled = ?, timeout_seconds = ?, max_cache_size_mb = ?, updated_at = ?
		WHERE id = ?
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
	repo.UpdatedAt = parseTime(now)
	return nil
}

func (s *SQLiteStore) DeleteCachedRepository(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM cached_repositories WHERE id = ?`, id)
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

func (s *SQLiteStore) CreateSession(ctx context.Context, sess *Session) error {
	if sess.TokenHash == "" {
		return fmt.Errorf("CreateSession: TokenHash required")
	}
	if sess.ExpiresAt.IsZero() {
		// GetSessionByTokenHash treats zero ExpiresAt as "no expiry", so a
		// row inserted without one would behave as an immortal session
		// until a cleanup sweep happened to notice it. Reject up-front.
		return fmt.Errorf("CreateSession: ExpiresAt required")
	}
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (token_hash, user_id, username, role, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, sess.TokenHash, sess.UserID, sess.Username, sess.Role,
		sqliteFmtAuthTime(sess.ExpiresAt),
		sqliteFmtAuthTime(sess.CreatedAt))
	return err
}

func (s *SQLiteStore) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT token_hash, user_id, username, role, expires_at, created_at
		FROM sessions WHERE token_hash = ?
	`, tokenHash)
	sess := &Session{}
	var expiresStr, createdStr string
	err := row.Scan(&sess.TokenHash, &sess.UserID, &sess.Username, &sess.Role, &expiresStr, &createdStr)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("session: %w", ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	sess.ExpiresAt = parseTime(expiresStr)
	sess.CreatedAt = parseTime(createdStr)
	if !sess.ExpiresAt.IsZero() && time.Now().After(sess.ExpiresAt) {
		// Treat expired rows as not-found; the cleanup goroutine will remove them.
		return nil, fmt.Errorf("session: %w", ErrNotFound)
	}
	return sess, nil
}

func (s *SQLiteStore) DeleteSession(ctx context.Context, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, tokenHash)
	return err
}

func (s *SQLiteStore) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	// Auth-state rows are written with sqliteAuthTimestampLayout (fixed-width
	// 3-digit fractional), so a direct lexicographic comparison is
	// chronologically correct and faster than wrapping with datetime().
	cutoff := sqliteFmtAuthTime(time.Now())
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- OAuth states ---

func (s *SQLiteStore) CreateOAuthState(ctx context.Context, st *OAuthState) error {
	if st.State == "" {
		return fmt.Errorf("CreateOAuthState: State required")
	}
	if st.Kind != OAuthStateKindLogin && st.Kind != OAuthStateKindBroker {
		return fmt.Errorf("CreateOAuthState: invalid Kind %q", st.Kind)
	}
	if st.ExpiresAt.IsZero() {
		return fmt.Errorf("CreateOAuthState: ExpiresAt required")
	}
	if st.CreatedAt.IsZero() {
		st.CreatedAt = time.Now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO oauth_states (state, kind, return_to, broker_redirect_uri, broker_downstream_state, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, st.State, st.Kind, st.ReturnTo, st.BrokerRedirectURI, st.BrokerDownstreamState,
		sqliteFmtAuthTime(st.ExpiresAt),
		sqliteFmtAuthTime(st.CreatedAt))
	return err
}

func (s *SQLiteStore) ConsumeOAuthState(ctx context.Context, state, kind string) (*OAuthState, error) {
	// DELETE ... RETURNING is atomic — exactly the read-and-delete semantics
	// we need so a state token cannot be replayed by a duplicate callback.
	// Mirrors PostgresStore.ConsumeOAuthState. SELECT-then-DELETE in a
	// transaction is not enough: two concurrent readers can both observe
	// the row before either DELETE runs.
	row := s.db.QueryRowContext(ctx, `
		DELETE FROM oauth_states WHERE state = ? AND kind = ?
		RETURNING state, kind, return_to, broker_redirect_uri, broker_downstream_state, expires_at, created_at
	`, state, kind)
	st := &OAuthState{}
	var expiresStr, createdStr string
	err := row.Scan(&st.State, &st.Kind, &st.ReturnTo, &st.BrokerRedirectURI, &st.BrokerDownstreamState, &expiresStr, &createdStr)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("oauth_state: %w", ErrNotFound)
	}
	if err != nil {
		return nil, err
	}
	st.ExpiresAt = parseTime(expiresStr)
	st.CreatedAt = parseTime(createdStr)
	if !st.ExpiresAt.IsZero() && time.Now().After(st.ExpiresAt) {
		return nil, fmt.Errorf("oauth_state: %w", ErrNotFound)
	}
	return st, nil
}

func (s *SQLiteStore) DeleteExpiredOAuthStates(ctx context.Context) (int64, error) {
	cutoff := sqliteFmtAuthTime(time.Now())
	res, err := s.db.ExecContext(ctx, `DELETE FROM oauth_states WHERE expires_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- Device authorization ---

func (s *SQLiteStore) CreateDeviceAuth(ctx context.Context, da *DeviceAuth) error {
	if da.DeviceCode == "" || da.UserCode == "" {
		return fmt.Errorf("CreateDeviceAuth: DeviceCode and UserCode required")
	}
	if da.ExpiresAt.IsZero() {
		return fmt.Errorf("CreateDeviceAuth: ExpiresAt required")
	}
	if da.Status == "" {
		da.Status = DeviceAuthStatusPending
	}
	if da.CreatedAt.IsZero() {
		da.CreatedAt = time.Now().UTC()
	}
	var lastPolledStr interface{}
	if da.LastPolledAt != nil {
		lastPolledStr = sqliteFmtAuthTime(*da.LastPolledAt)
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
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, da.DeviceCode, da.UserCode, da.Status, sessTok, username, lastPolledStr,
		sqliteFmtAuthTime(da.ExpiresAt),
		sqliteFmtAuthTime(da.CreatedAt))
	return err
}

func (s *SQLiteStore) GetDeviceAuthByDeviceCode(ctx context.Context, deviceCode string) (*DeviceAuth, error) {
	return s.scanDeviceAuth(ctx, `
		SELECT device_code, user_code, status, session_token, username, last_polled_at, expires_at, created_at
		FROM cli_device_authorizations WHERE device_code = ?
	`, deviceCode)
}

func (s *SQLiteStore) GetDeviceAuthByUserCode(ctx context.Context, userCode string) (*DeviceAuth, error) {
	return s.scanDeviceAuth(ctx, `
		SELECT device_code, user_code, status, session_token, username, last_polled_at, expires_at, created_at
		FROM cli_device_authorizations WHERE user_code = ?
	`, userCode)
}

func (s *SQLiteStore) scanDeviceAuth(ctx context.Context, query, arg string) (*DeviceAuth, error) {
	row := s.db.QueryRowContext(ctx, query, arg)
	da := &DeviceAuth{}
	var sessTok, username sql.NullString
	var lastPolledStr sql.NullString
	var expiresStr, createdStr string
	err := row.Scan(&da.DeviceCode, &da.UserCode, &da.Status, &sessTok, &username, &lastPolledStr, &expiresStr, &createdStr)
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
	if lastPolledStr.Valid {
		t := parseTime(lastPolledStr.String)
		da.LastPolledAt = &t
	}
	da.ExpiresAt = parseTime(expiresStr)
	da.CreatedAt = parseTime(createdStr)
	if !da.ExpiresAt.IsZero() && time.Now().After(da.ExpiresAt) {
		return nil, fmt.Errorf("device_auth: %w", ErrNotFound)
	}
	return da, nil
}

func (s *SQLiteStore) UpdateDeviceAuth(ctx context.Context, da *DeviceAuth) error {
	var lastPolledStr interface{}
	if da.LastPolledAt != nil {
		lastPolledStr = sqliteFmtAuthTime(*da.LastPolledAt)
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
		SET status = ?, session_token = ?, username = ?, last_polled_at = ?, expires_at = ?
		WHERE device_code = ?
	`, da.Status, sessTok, username, lastPolledStr,
		sqliteFmtAuthTime(da.ExpiresAt),
		da.DeviceCode)
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

func (s *SQLiteStore) DeleteDeviceAuth(ctx context.Context, deviceCode string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM cli_device_authorizations WHERE device_code = ?`, deviceCode)
	return err
}

func (s *SQLiteStore) DeleteExpiredDeviceAuths(ctx context.Context) (int64, error) {
	cutoff := sqliteFmtAuthTime(time.Now())
	res, err := s.db.ExecContext(ctx, `DELETE FROM cli_device_authorizations WHERE expires_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Ensure SQLiteStore implements all required interfaces.
var (
	_ Store             = (*SQLiteStore)(nil)
	_ MigrationExecutor = (*SQLiteStore)(nil)
)
