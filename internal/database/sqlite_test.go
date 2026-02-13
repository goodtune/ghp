package database

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) *SQLiteStore {
	t.Helper()
	dir := t.TempDir()
	dsn := filepath.Join(dir, "test.db")
	store, err := NewSQLiteStore(dsn)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	// Run migrations.
	ctx := context.Background()
	if err := store.EnsureMigrationsTable(ctx); err != nil {
		t.Fatalf("EnsureMigrationsTable: %v", err)
	}
	migrator := NewMigrator(store, "sqlite")
	if err := migrator.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return store
}

func TestUserCRUD(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	user := &User{
		GitHubID:      12345,
		GitHubUsername: "alice",
		GitHubEmail:   "alice@example.com",
		Role:          "user",
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

func TestProxyTokenCRUD(t *testing.T) {
	store := newTestStore(t)
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

	// Create a proxy token.
	scopes := json.RawMessage(`{"contents":"read","pulls":"write"}`)
	pt := &ProxyToken{
		TokenHash:     "sha256hash123",
		TokenPrefix:   "ghp_a1b2",
		UserID:        user.ID,
		GitHubTokenID: gt.ID,
		Repository:    "org/repo",
		Scopes:        scopes,
		SessionID:     "test-session",
		ExpiresAt:     time.Now().Add(24 * time.Hour),
	}
	if err := store.CreateProxyToken(ctx, pt); err != nil {
		t.Fatal(err)
	}

	// Get by hash.
	got, err := store.GetProxyTokenByHash(ctx, "sha256hash123")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected token, got nil")
	}
	if got.Repository != "org/repo" {
		t.Errorf("repository = %q, want org/repo", got.Repository)
	}
	if got.TokenPrefix != "ghp_a1b2" {
		t.Errorf("prefix = %q, want ghp_a1b2", got.TokenPrefix)
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
	if len(tokens) != 1 {
		t.Errorf("ListProxyTokens = %d, want 1", len(tokens))
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

func TestMigrations(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "test.db")
	store, err := NewSQLiteStore(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	ctx := context.Background()
	if err := store.EnsureMigrationsTable(ctx); err != nil {
		t.Fatal(err)
	}

	migrator := NewMigrator(store, "sqlite")

	// Check pending.
	pending, err := migrator.PendingMigrations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) == 0 {
		t.Fatal("expected pending migrations")
	}

	// Run.
	if err := migrator.Migrate(ctx); err != nil {
		t.Fatal(err)
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

	// No more pending.
	pending2, err := migrator.PendingMigrations(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending2) != 0 {
		t.Errorf("expected 0 pending, got %d", len(pending2))
	}
}

func TestAuditLog(t *testing.T) {
	store := newTestStore(t)
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

// Ensure temporary files are cleaned up.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
