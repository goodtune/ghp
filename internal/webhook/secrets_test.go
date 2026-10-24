package webhook

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
)

func newSecretTestStore(t *testing.T) database.Store {
	t.Helper()
	store, err := database.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	if err := database.NewMigrator(store, "sqlite").Migrate(context.Background()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

func TestStoreSecretSource_Candidates(t *testing.T) {
	ctx := context.Background()
	store := newSecretTestStore(t)
	enc := crypto.NewPassthroughEncryptor()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	mustCreate := func(name string, appID int64, secret string) *database.App {
		a := &database.App{Name: name, AppID: appID, WebhookSecret: secret}
		if err := store.CreateApp(ctx, a); err != nil {
			t.Fatalf("CreateApp %s: %v", name, err)
		}
		return a
	}
	withSecret := mustCreate("with-secret", 111, "s-111")
	mustCreate("no-secret", 222, "")
	other := mustCreate("other", 333, "s-333")

	t.Run("integration target with matching app", func(t *testing.T) {
		src := NewStoreSecretSource(store, enc, "global", logger)
		c, err := src.Candidates(ctx, TargetTypeIntegration, "111")
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 2 {
			t.Fatalf("got %d candidates, want 2 (app + global): %+v", len(c), c)
		}
		if c[0].AppRecordID != withSecret.ID || string(c[0].Secret) != "s-111" || c[0].GitHubAppID != 111 || c[0].AppName != "with-secret" {
			t.Errorf("first candidate = %+v, want app %s", c[0], withSecret.ID)
		}
		if c[1].AppRecordID != "" || string(c[1].Secret) != "global" {
			t.Errorf("second candidate = %+v, want global", c[1])
		}
	})

	t.Run("integration target with app lacking a secret falls back to global only", func(t *testing.T) {
		src := NewStoreSecretSource(store, enc, "global", logger)
		c, err := src.Candidates(ctx, TargetTypeIntegration, "222")
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 1 || c[0].AppRecordID != "" {
			t.Errorf("got %+v, want only global", c)
		}
	})

	t.Run("integration target unknown app without global yields nothing", func(t *testing.T) {
		src := NewStoreSecretSource(store, enc, "", logger)
		c, err := src.Candidates(ctx, TargetTypeIntegration, "999")
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 0 {
			t.Errorf("got %+v, want none", c)
		}
	})

	t.Run("non-integration target tries global then every app secret", func(t *testing.T) {
		src := NewStoreSecretSource(store, enc, "global", logger)
		c, err := src.Candidates(ctx, "repository", "42")
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 3 {
			t.Fatalf("got %d candidates, want 3: %+v", len(c), c)
		}
		if c[0].AppRecordID != "" {
			t.Errorf("first candidate should be global, got %+v", c[0])
		}
		ids := map[string]bool{c[1].AppRecordID: true, c[2].AppRecordID: true}
		if !ids[withSecret.ID] || !ids[other.ID] {
			t.Errorf("expected both apps with secrets, got %+v", c[1:])
		}
	})

	t.Run("cache is used until invalidated", func(t *testing.T) {
		src := NewStoreSecretSource(store, enc, "", logger)
		if _, err := src.Candidates(ctx, TargetTypeIntegration, "111"); err != nil {
			t.Fatal(err)
		}
		fresh := mustCreate("late", 444, "s-444")
		c, _ := src.Candidates(ctx, TargetTypeIntegration, "444")
		if len(c) != 0 {
			t.Errorf("expected cached view to miss the new app, got %+v", c)
		}
		src.Invalidate()
		c, _ = src.Candidates(ctx, TargetTypeIntegration, "444")
		if len(c) != 1 || c[0].AppRecordID != fresh.ID {
			t.Errorf("after Invalidate expected new app, got %+v", c)
		}
	})
}

func TestStoreSecretSource_DecryptsSecrets(t *testing.T) {
	ctx := context.Background()
	store := newSecretTestStore(t)
	enc, err := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := enc.Encrypt("plain-secret")
	if err != nil {
		t.Fatal(err)
	}
	a := &database.App{Name: "enc", AppID: 555, WebhookSecret: ciphertext}
	if err := store.CreateApp(ctx, a); err != nil {
		t.Fatal(err)
	}
	// A corrupt record must be skipped, not fatal.
	bad := &database.App{Name: "bad", AppID: 556, WebhookSecret: "not-ciphertext"}
	if err := store.CreateApp(ctx, bad); err != nil {
		t.Fatal(err)
	}

	src := NewStoreSecretSource(store, enc, "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	c, err := src.Candidates(ctx, TargetTypeIntegration, "555")
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != 1 || string(c[0].Secret) != "plain-secret" {
		t.Errorf("got %+v, want decrypted secret", c)
	}
	c, err = src.Candidates(ctx, TargetTypeIntegration, "556")
	if err != nil {
		t.Fatal(err)
	}
	if len(c) != 0 {
		t.Errorf("corrupt secret should yield no candidates, got %+v", c)
	}
}
