package database

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

// newTestPostgresStore creates a PostgresStore connected to a test database.
// Tests are skipped when GHP_TEST_POSTGRES_DSN is not set.
func newTestPostgresStore(t *testing.T) *PostgresStore {
	t.Helper()
	dsn := os.Getenv("GHP_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("GHP_TEST_POSTGRES_DSN not set; skipping PostgreSQL tests")
	}

	store, err := NewPostgresStore(dsn)
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	// Drop and recreate tables for a clean slate.
	ctx := context.Background()
	for _, stmt := range []string{
		"DROP TABLE IF EXISTS audit_log",
		"DROP TABLE IF EXISTS proxy_tokens",
		"DROP TYPE IF EXISTS token_type",
		"DROP TABLE IF EXISTS github_tokens",
		"DROP TABLE IF EXISTS users",
		"DROP TABLE IF EXISTS schema_migrations",
	} {
		if _, err := store.db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("cleanup %q: %v", stmt, err)
		}
	}

	// Run migrations.
	if err := store.EnsureMigrationsTable(ctx); err != nil {
		t.Fatalf("EnsureMigrationsTable: %v", err)
	}
	migrator := NewMigrator(store, "postgres")
	if err := migrator.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return store
}

func TestPostgresUserCRUD(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()

	user := &User{
		GitHubID:       12345,
		GitHubUsername: "alice",
		GitHubEmail:    "alice@example.com",
		Role:           "user",
	}

	if err := store.UpsertUser(ctx, user); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	if user.ID == "" {
		t.Fatal("expected ID to be set")
	}

	// Get by GitHub ID.
	got, err := store.GetUserByGitHubID(ctx, 12345)
	if err != nil {
		t.Fatalf("GetUserByGitHubID: %v", err)
	}
	if got == nil {
		t.Fatal("expected user, got nil")
	}
	if got.GitHubUsername != "alice" {
		t.Errorf("username = %q, want alice", got.GitHubUsername)
	}

	// Get by ID.
	got2, err := store.GetUserByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if got2 == nil || got2.GitHubUsername != "alice" {
		t.Error("GetUserByID failed")
	}

	// Upsert again (update).
	user.GitHubUsername = "alice-updated"
	if err := store.UpsertUser(ctx, user); err != nil {
		t.Fatalf("UpsertUser (update): %v", err)
	}
	got3, err := store.GetUserByGitHubID(ctx, 12345)
	if err != nil {
		t.Fatal(err)
	}
	if got3.GitHubUsername != "alice-updated" {
		t.Errorf("username after update = %q, want alice-updated", got3.GitHubUsername)
	}

	// List users.
	users, err := store.ListUsers(ctx)
	if err != nil {
		t.Fatalf("ListUsers: %v", err)
	}
	if len(users) != 1 {
		t.Errorf("ListUsers returned %d users, want 1", len(users))
	}
}

func TestPostgresProxyTokenCRUD(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()

	// Create a user first.
	user := &User{GitHubID: 1, GitHubUsername: "bob", Role: "user"}
	if err := store.UpsertUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	// Create a GitHub token.
	gt := &GitHubToken{
		UserID:                user.ID,
		AccessToken:           "enc_access",
		RefreshToken:          "enc_refresh",
		AccessTokenExpiresAt:  time.Now().Add(8 * time.Hour),
		RefreshTokenExpiresAt: time.Now().Add(180 * 24 * time.Hour),
		Scopes:                "",
	}
	if err := store.UpsertGitHubToken(ctx, gt); err != nil {
		t.Fatal(err)
	}

	// Test proxy token (ghx_ type).
	scopes := json.RawMessage(`{"contents":"read","pulls":"write"}`)
	repos := json.RawMessage(`["org/repo"]`)
	pt := &ProxyToken{
		TokenHash:     "sha256hash123",
		TokenPrefix:   "ghx_a1b2",
		TokenType:     "proxy",
		UserID:        &user.ID,
		GitHubTokenID: &gt.ID,
		Repositories:  repos,
		Scopes:        scopes,
		SessionID:     "test-session",
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	if err := store.CreateProxyToken(ctx, pt); err != nil {
		t.Fatal(err)
	}

	got, err := store.GetProxyTokenByHash(ctx, "sha256hash123")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected token, got nil")
	}
	if got.TokenType != "proxy" {
		t.Errorf("token_type = %q, want proxy", got.TokenType)
	}
	if got.TokenPrefix != "ghx_a1b2" {
		t.Errorf("prefix = %q, want ghx_a1b2", got.TokenPrefix)
	}

	var gotRepos []string
	if err := json.Unmarshal(got.Repositories, &gotRepos); err != nil {
		t.Fatal(err)
	}
	if len(gotRepos) != 1 || gotRepos[0] != "org/repo" {
		t.Errorf("repositories = %v, want [org/repo]", gotRepos)
	}

	// Test agent token (gha_ type) with installation_id and no github_token.
	installID := int64(12345)
	agentRepos := json.RawMessage(`["org/repo1","org/repo2"]`)
	at := &ProxyToken{
		TokenHash:      "sha256hash456",
		TokenPrefix:    "gha_c3d4",
		TokenType:      "agent",
		UserID:         &user.ID,
		InstallationID: &installID,
		Repositories:   agentRepos,
		Scopes:         json.RawMessage(`{"contents":"read"}`),
		SessionID:      "admin-session",
		ExpiresAt:      time.Now().Add(365 * 24 * time.Hour),
	}
	if err := store.CreateProxyToken(ctx, at); err != nil {
		t.Fatal(err)
	}

	gotAgent, err := store.GetProxyTokenByHash(ctx, "sha256hash456")
	if err != nil {
		t.Fatal(err)
	}
	if gotAgent.TokenType != "agent" {
		t.Errorf("token_type = %q, want agent", gotAgent.TokenType)
	}
	if gotAgent.InstallationID == nil || *gotAgent.InstallationID != 12345 {
		t.Errorf("installation_id = %v, want 12345", gotAgent.InstallationID)
	}

	// Update usage.
	if err := store.UpdateProxyTokenUsage(ctx, pt.ID); err != nil {
		t.Fatal(err)
	}
	got2, _ := store.GetProxyTokenByID(ctx, pt.ID)
	if got2.RequestCount != 1 {
		t.Errorf("request_count = %d, want 1", got2.RequestCount)
	}
	if got2.LastUsedAt == nil {
		t.Error("last_used_at should be set")
	}

	// List.
	tokens, err := store.ListProxyTokens(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 {
		t.Errorf("ListProxyTokens = %d, want 2", len(tokens))
	}

	// Revoke.
	if err := store.RevokeProxyToken(ctx, pt.ID); err != nil {
		t.Fatal(err)
	}
	got3, _ := store.GetProxyTokenByID(ctx, pt.ID)
	if got3.RevokedAt == nil {
		t.Error("revoked_at should be set")
	}

	// Double revoke should fail.
	if err := store.RevokeProxyToken(ctx, pt.ID); err == nil {
		t.Error("expected error on double revoke")
	}
}

func TestPostgresMigrations(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()

	migrator := NewMigrator(store, "postgres")

	// After setup, no pending migrations should remain.
	pending, err := migrator.PendingMigrations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Errorf("expected 0 pending, got %d", len(pending))
	}

	// Check status.
	statuses, err := migrator.Status(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range statuses {
		if !s.Applied {
			t.Errorf("migration %s not applied", s.Name)
		}
	}
}

func TestPostgresAuditLog(t *testing.T) {
	store := newTestPostgresStore(t)
	ctx := context.Background()

	user := &User{GitHubID: 1, GitHubUsername: "charlie", Role: "user"}
	if err := store.UpsertUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	entry := &AuditEntry{
		UserID:     user.ID,
		Action:     "proxy_request",
		Method:     "GET",
		Path:       "/repos/org/repo/pulls",
		Repository: "org/repo",
		StatusCode: 200,
		DurationMS: 42,
		SessionID:  "test",
	}
	if err := store.CreateAuditEntry(ctx, entry); err != nil {
		t.Fatal(err)
	}

	entries, err := store.ListAuditEntries(ctx, AuditFilter{UserID: user.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("ListAuditEntries = %d, want 1", len(entries))
	}
	if entries[0].Action != "proxy_request" {
		t.Errorf("action = %q, want proxy_request", entries[0].Action)
	}
}
