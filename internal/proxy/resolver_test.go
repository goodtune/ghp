package proxy

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/token"
)

func TestProxyTokenResolver(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	// Set up encryptor with a test key.
	enc, err := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}

	// Create a user.
	user := &database.User{GitHubID: 1, GitHubUsername: "alice", Role: "user"}
	if err := store.UpsertUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	// Create a GitHub token with an encrypted access token.
	encAccess, err := enc.Encrypt("real-github-pat")
	if err != nil {
		t.Fatal(err)
	}
	gt := &database.GitHubToken{
		UserID:                user.ID,
		AccessToken:           encAccess,
		RefreshToken:          "enc_refresh",
		AccessTokenExpiresAt:  time.Now().Add(8 * time.Hour),
		RefreshTokenExpiresAt: time.Now().Add(180 * 24 * time.Hour),
	}
	if err := store.UpsertGitHubToken(ctx, gt); err != nil {
		t.Fatal(err)
	}

	// Create a proxy token via the token service.
	tokenSvc := token.NewService(store, 7*24*time.Hour, false)
	result, err := tokenSvc.Create(ctx, token.CreateRequest{
		UserID:        user.ID,
		GitHubTokenID: gt.ID,
		Repository:    "org/repo",
		Scopes:        map[string]string{"contents": "read"},
		Duration:      24 * time.Hour,
		SessionID:     "test-session",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Resolve the token.
	resolver := NewProxyTokenResolver(tokenSvc, store, enc, nil)
	plaintext, err := resolver.ResolveToGitHubToken(ctx, result.Token)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext != "real-github-pat" {
		t.Errorf("expected 'real-github-pat', got %q", plaintext)
	}
}

func TestProxyTokenResolver_InvalidToken(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	enc, err := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}

	tokenSvc := token.NewService(store, 7*24*time.Hour, false)
	resolver := NewProxyTokenResolver(tokenSvc, store, enc, nil)

	_, err = resolver.ResolveToGitHubToken(ctx, "ghx_nonexistenttoken1234567890abcdefghijklmno")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func newTestStore(t *testing.T) database.Store {
	t.Helper()
	dir := t.TempDir()
	dsn := filepath.Join(dir, "test.db")
	store, err := database.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })

	ctx := context.Background()
	migrator := database.NewMigrator(store, "sqlite")
	if err := migrator.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return store
}
