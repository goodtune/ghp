package github

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/database"
)

// mockStore implements database.Store with a configurable ListApps result.
// All other methods panic to catch unexpected calls.
type mockStore struct {
	apps []*database.App
}

func (m *mockStore) ListApps(ctx context.Context) ([]*database.App, error) {
	return m.apps, nil
}

func (m *mockStore) CreateApp(ctx context.Context, app *database.App) error        { panic("unexpected") }
func (m *mockStore) GetAppByID(ctx context.Context, id string) (*database.App, error) {
	panic("unexpected")
}
func (m *mockStore) GetDefaultApp(ctx context.Context) (*database.App, error) { panic("unexpected") }
func (m *mockStore) UpdateApp(ctx context.Context, app *database.App) error    { panic("unexpected") }
func (m *mockStore) DeleteApp(ctx context.Context, id string) error            { panic("unexpected") }
func (m *mockStore) SetDefaultApp(ctx context.Context, appID string) error     { panic("unexpected") }

func (m *mockStore) UpsertUser(ctx context.Context, user *database.User) error { panic("unexpected") }
func (m *mockStore) GetUserByGitHubID(ctx context.Context, githubID int64) (*database.User, error) {
	panic("unexpected")
}
func (m *mockStore) GetUserByID(ctx context.Context, id string) (*database.User, error) {
	panic("unexpected")
}
func (m *mockStore) ListUsers(ctx context.Context) ([]*database.User, error) { panic("unexpected") }
func (m *mockStore) SyncAdminRoles(ctx context.Context, admins []string) error { panic("unexpected") }

func (m *mockStore) UpsertGitHubToken(ctx context.Context, token *database.GitHubToken) error {
	panic("unexpected")
}
func (m *mockStore) GetGitHubToken(ctx context.Context, userID string) (*database.GitHubToken, error) {
	panic("unexpected")
}
func (m *mockStore) GetGitHubTokenByID(ctx context.Context, id string) (*database.GitHubToken, error) {
	panic("unexpected")
}

func (m *mockStore) CreateProxyToken(ctx context.Context, token *database.ProxyToken) error {
	panic("unexpected")
}
func (m *mockStore) GetProxyTokenByHash(ctx context.Context, hash string) (*database.ProxyToken, error) {
	panic("unexpected")
}
func (m *mockStore) GetProxyTokenByID(ctx context.Context, id string) (*database.ProxyToken, error) {
	panic("unexpected")
}
func (m *mockStore) ListProxyTokens(ctx context.Context, userID string) ([]*database.ProxyToken, error) {
	panic("unexpected")
}
func (m *mockStore) ListAllProxyTokens(ctx context.Context) ([]*database.ProxyToken, error) {
	panic("unexpected")
}
func (m *mockStore) ListActiveProxyTokens(ctx context.Context) ([]*database.ProxyToken, error) {
	panic("unexpected")
}
func (m *mockStore) RevokeProxyToken(ctx context.Context, id string) error { panic("unexpected") }
func (m *mockStore) UpdateProxyTokenAppID(ctx context.Context, id string, appID string) error {
	panic("unexpected")
}
func (m *mockStore) Close() error { return nil }

// makeApp creates a minimal App record with a valid private key for testing.
func makeApp(id, name string, appID int64, isDefault bool) *database.App {
	return &database.App{
		ID:        id,
		Name:      name,
		AppID:     appID,
		PrivateKey: testRSAKey,
		IsDefault: isDefault,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

func newTestRegistry(apps []*database.App) *AppRegistry {
	return NewAppRegistry(&mockStore{apps: apps}, nil, slog.Default())
}

func TestAppRegistry_LoadAll_SingleDefault(t *testing.T) {
	app := makeApp("app-1", "Test App", 1, true)
	r := newTestRegistry([]*database.App{app})

	if err := r.LoadAll(context.Background()); err != nil {
		t.Fatal(err)
	}

	if r.Count() != 1 {
		t.Errorf("expected 1 provider, got %d", r.Count())
	}
	if r.GetDefaultID() != "app-1" {
		t.Errorf("expected default ID app-1, got %q", r.GetDefaultID())
	}
	if _, err := r.GetDefault(); err != nil {
		t.Errorf("GetDefault() returned error: %v", err)
	}
}

func TestAppRegistry_LoadAll_ResetsStateOnSecondCall(t *testing.T) {
	app1 := makeApp("app-1", "App One", 1, true)
	r := newTestRegistry([]*database.App{app1})

	if err := r.LoadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Count() != 1 {
		t.Fatalf("expected 1 provider after first load, got %d", r.Count())
	}

	// Second call with a different set of apps — state should be fully replaced,
	// not accumulated.
	app2 := makeApp("app-2", "App Two", 2, false)
	r.store = &mockStore{apps: []*database.App{app2}}

	if err := r.LoadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Count() != 1 {
		t.Errorf("expected 1 provider after second load, got %d", r.Count())
	}
	if r.GetDefaultID() != "" {
		t.Errorf("expected no default after second load (app2 not default), got %q", r.GetDefaultID())
	}
	if _, err := r.Get("app-1"); err == nil {
		t.Error("app-1 should not exist after second LoadAll, but Get succeeded")
	}
	if _, err := r.Get("app-2"); err != nil {
		t.Errorf("app-2 should be loaded after second LoadAll: %v", err)
	}
}

func TestAppRegistry_LoadAll_NoDefault(t *testing.T) {
	app := makeApp("app-1", "App One", 1, false)
	r := newTestRegistry([]*database.App{app})

	if err := r.LoadAll(context.Background()); err != nil {
		t.Fatal(err)
	}

	if r.GetDefaultID() != "" {
		t.Errorf("expected empty default ID, got %q", r.GetDefaultID())
	}
	// With exactly one provider and no explicit default, GetDefault should
	// return the single provider.
	if _, err := r.GetDefault(); err != nil {
		t.Errorf("GetDefault() with single non-default provider: %v", err)
	}
}

func TestAppRegistry_LoadAll_InvalidKeySkipped(t *testing.T) {
	bad := &database.App{
		ID:        "bad-app",
		Name:      "Bad App",
		AppID:     99,
		PrivateKey: "not-a-valid-key",
		IsDefault: true,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	r := newTestRegistry([]*database.App{bad})

	if err := r.LoadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	// App with invalid key should be skipped.
	if r.Count() != 0 {
		t.Errorf("expected 0 providers (invalid key skipped), got %d", r.Count())
	}
	// defaultID should not be set if the app was skipped.
	if r.GetDefaultID() != "" {
		t.Errorf("expected empty defaultID when only app has invalid key, got %q", r.GetDefaultID())
	}
}

func TestAppRegistry_Reload_RemovesDeletedApps(t *testing.T) {
	app1 := makeApp("app-1", "App One", 1, true)
	app2 := makeApp("app-2", "App Two", 2, false)
	store := &mockStore{apps: []*database.App{app1, app2}}
	r := NewAppRegistry(store, nil, slog.Default())

	if err := r.LoadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Count() != 2 {
		t.Fatalf("expected 2 providers, got %d", r.Count())
	}

	// Remove app-2 from the store and reload.
	store.apps = []*database.App{app1}
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Count() != 1 {
		t.Errorf("expected 1 provider after reload, got %d", r.Count())
	}
	if _, err := r.Get("app-2"); err == nil {
		t.Error("app-2 should have been removed on reload")
	}
}

func TestAppRegistry_Reload_UpdatesDefaultID(t *testing.T) {
	app1 := makeApp("app-1", "App One", 1, true)
	app2 := makeApp("app-2", "App Two", 2, false)
	store := &mockStore{apps: []*database.App{app1, app2}}
	r := NewAppRegistry(store, nil, slog.Default())

	if err := r.LoadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.GetDefaultID() != "app-1" {
		t.Fatalf("expected default app-1, got %q", r.GetDefaultID())
	}

	// Change the default to app-2.
	app1.IsDefault = false
	app2.IsDefault = true
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.GetDefaultID() != "app-2" {
		t.Errorf("expected default app-2 after reload, got %q", r.GetDefaultID())
	}
}

func TestAppRegistry_Reload_ClearsDefaultWhenNoneMarked(t *testing.T) {
	app := makeApp("app-1", "App One", 1, true)
	store := &mockStore{apps: []*database.App{app}}
	r := NewAppRegistry(store, nil, slog.Default())

	if err := r.LoadAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.GetDefaultID() != "app-1" {
		t.Fatalf("expected default app-1, got %q", r.GetDefaultID())
	}

	// Clear the default flag — no app is default after reload.
	app.IsDefault = false
	if err := r.Reload(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.GetDefaultID() != "" {
		t.Errorf("expected empty defaultID after reload with no defaults, got %q", r.GetDefaultID())
	}
}

func TestAppRegistry_GetDefault_MultipleProviders_NoDefault(t *testing.T) {
	app1 := makeApp("app-1", "App One", 1, false)
	app2 := makeApp("app-2", "App Two", 2, false)
	r := newTestRegistry([]*database.App{app1, app2})

	if err := r.LoadAll(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Multiple providers, none is default — should return an error.
	if _, err := r.GetDefault(); err == nil {
		t.Error("expected error from GetDefault() with multiple providers and no default")
	}
}

func TestAppRegistry_Get_SpecificApp(t *testing.T) {
	app1 := makeApp("app-1", "App One", 1, false)
	app2 := makeApp("app-2", "App Two", 2, false)
	r := newTestRegistry([]*database.App{app1, app2})

	if err := r.LoadAll(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := r.Get("app-1"); err != nil {
		t.Errorf("Get(app-1) failed: %v", err)
	}
	if _, err := r.Get("app-2"); err != nil {
		t.Errorf("Get(app-2) failed: %v", err)
	}
	if _, err := r.Get("nonexistent"); err == nil {
		t.Error("expected error for nonexistent app ID")
	}
}
