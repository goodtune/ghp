package database

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

func timePtr(t time.Time) *time.Time { return &t }

// testStoreContract runs the full CRUD test suite against any Store implementation.
// Each backend test file calls this with its own Store instance.
func testStoreContract(t *testing.T, store Store) {
	t.Run("AppCRUD", func(t *testing.T) { testAppCRUD(t, store) })
	t.Run("SetDefaultApp", func(t *testing.T) { testSetDefaultApp(t, store) })
	t.Run("UserCRUD", func(t *testing.T) { testUserCRUD(t, store) })
	t.Run("ProxyTokenCRUD", func(t *testing.T) { testProxyTokenCRUD(t, store) })
	t.Run("ProxyTokenWithAppID", func(t *testing.T) { testProxyTokenWithAppID(t, store) })
	t.Run("ProxyTokenNoExpiry", func(t *testing.T) { testProxyTokenNoExpiry(t, store) })
	t.Run("UpdateProxyTokenAppID", func(t *testing.T) { testUpdateProxyTokenAppID(t, store) })
	t.Run("UpdateProxyTokenScopes", func(t *testing.T) { testUpdateProxyTokenScopes(t, store) })
	t.Run("GitHubTokenAppID", func(t *testing.T) { testGitHubTokenAppID(t, store) })
	t.Run("SyncAdminRoles", func(t *testing.T) { testSyncAdminRoles(t, store) })
	t.Run("CachedRepositoryCRUD", func(t *testing.T) { testCachedRepositoryCRUD(t, store) })
	t.Run("DeleteExpiredProxyTokens", func(t *testing.T) { testDeleteExpiredProxyTokens(t, store) })
	t.Run("SessionCRUD", func(t *testing.T) { testSessionCRUD(t, store) })
	t.Run("OAuthStateConsume", func(t *testing.T) { testOAuthStateConsume(t, store) })
	t.Run("DeviceAuthCRUD", func(t *testing.T) { testDeviceAuthCRUD(t, store) })
}

func testAppCRUD(t *testing.T, store Store) {
	ctx := context.Background()

	// Create.
	app := &App{
		Name:         "Test App",
		AppID:        12345,
		ClientID:     "Iv1.abc123",
		ClientSecret: "encrypted_secret",
		PrivateKey:   "encrypted_key",
		BaseURL:      "https://api.github.com",
		IsDefault:    true,
	}
	if err := store.CreateApp(ctx, app); err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	if app.ID == "" {
		t.Fatal("expected ID to be set")
	}
	if app.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be set")
	}

	// Get by ID.
	got, err := store.GetAppByID(ctx, app.ID)
	if err != nil {
		t.Fatalf("GetAppByID: %v", err)
	}
	if got == nil {
		t.Fatal("expected app, got nil")
	}
	if got.Name != "Test App" {
		t.Errorf("name = %q, want Test App", got.Name)
	}
	if got.AppID != 12345 {
		t.Errorf("app_id = %d, want 12345", got.AppID)
	}
	if got.ClientID != "Iv1.abc123" {
		t.Errorf("client_id = %q, want Iv1.abc123", got.ClientID)
	}
	if got.ClientSecret != "encrypted_secret" {
		t.Errorf("client_secret = %q, want encrypted_secret", got.ClientSecret)
	}
	if got.PrivateKey != "encrypted_key" {
		t.Errorf("private_key = %q, want encrypted_key", got.PrivateKey)
	}
	if got.BaseURL != "https://api.github.com" {
		t.Errorf("base_url = %q, want https://api.github.com", got.BaseURL)
	}
	if !got.IsDefault {
		t.Error("expected is_default = true")
	}
	if got.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set on retrieved app")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("expected UpdatedAt to be set on retrieved app")
	}

	// Get default.
	def, err := store.GetDefaultApp(ctx)
	if err != nil {
		t.Fatalf("GetDefaultApp: %v", err)
	}
	if def == nil {
		t.Fatal("expected default app, got nil")
	}
	if def.ID != app.ID {
		t.Errorf("default app ID = %q, want %q", def.ID, app.ID)
	}

	// List.
	apps, err := store.ListApps(ctx)
	if err != nil {
		t.Fatalf("ListApps: %v", err)
	}
	if len(apps) != 1 {
		t.Errorf("ListApps returned %d, want 1", len(apps))
	}

	// Update.
	app.Name = "Updated App"
	app.IsDefault = false
	if err := store.UpdateApp(ctx, app); err != nil {
		t.Fatalf("UpdateApp: %v", err)
	}
	got2, err := store.GetAppByID(ctx, app.ID)
	if err != nil {
		t.Fatalf("GetAppByID after update: %v", err)
	}
	if got2.Name != "Updated App" {
		t.Errorf("name after update = %q, want Updated App", got2.Name)
	}
	if got2.CreatedAt.IsZero() {
		t.Error("expected CreatedAt preserved after update")
	}
	if got2.UpdatedAt.IsZero() {
		t.Error("expected UpdatedAt set after update")
	}

	// Create a second app (not default — the unique index enforces at most one).
	app2 := &App{
		Name:      "Second App",
		AppID:     67890,
		IsDefault: false,
	}
	if err := store.CreateApp(ctx, app2); err != nil {
		t.Fatalf("CreateApp (second): %v", err)
	}

	apps2, err := store.ListApps(ctx)
	if err != nil {
		t.Fatalf("ListApps: %v", err)
	}
	if len(apps2) != 2 {
		t.Errorf("ListApps returned %d, want 2", len(apps2))
	}

	// Delete.
	if err := store.DeleteApp(ctx, app.ID); err != nil {
		t.Fatalf("DeleteApp: %v", err)
	}
	got3, err := store.GetAppByID(ctx, app.ID)
	if err != nil {
		t.Fatalf("GetAppByID after delete: %v", err)
	}
	if got3 != nil {
		t.Error("expected nil after delete")
	}

	// Delete non-existent (use a valid UUID so Postgres doesn't reject the format).
	if err := store.DeleteApp(ctx, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound deleting non-existent app, got: %v", err)
	}

	// Cleanup second app.
	if err := store.DeleteApp(ctx, app2.ID); err != nil {
		t.Fatalf("DeleteApp (second): %v", err)
	}
}

func testSetDefaultApp(t *testing.T, store Store) {
	ctx := context.Background()

	// Create two apps, neither is default.
	app1 := &App{Name: "SetDefault App1", AppID: 10001, PrivateKey: "key1"}
	if err := store.CreateApp(ctx, app1); err != nil {
		t.Fatalf("CreateApp(app1): %v", err)
	}
	app2 := &App{Name: "SetDefault App2", AppID: 10002, PrivateKey: "key2"}
	if err := store.CreateApp(ctx, app2); err != nil {
		t.Fatalf("CreateApp(app2): %v", err)
	}

	// No default initially.
	def, err := store.GetDefaultApp(ctx)
	if err != nil {
		t.Fatalf("GetDefaultApp: %v", err)
	}
	if def != nil {
		t.Fatalf("expected no default app, got %q", def.ID)
	}

	// Set app1 as default.
	if err := store.SetDefaultApp(ctx, app1.ID); err != nil {
		t.Fatalf("SetDefaultApp(app1): %v", err)
	}

	got1, err := store.GetAppByID(ctx, app1.ID)
	if err != nil {
		t.Fatalf("GetAppByID(app1): %v", err)
	}
	if !got1.IsDefault {
		t.Error("expected app1 to be default after SetDefaultApp")
	}

	got2, err := store.GetAppByID(ctx, app2.ID)
	if err != nil {
		t.Fatalf("GetAppByID(app2): %v", err)
	}
	if got2.IsDefault {
		t.Error("expected app2 to NOT be default")
	}

	// Switch default to app2.
	if err := store.SetDefaultApp(ctx, app2.ID); err != nil {
		t.Fatalf("SetDefaultApp(app2): %v", err)
	}

	got1, err = store.GetAppByID(ctx, app1.ID)
	if err != nil {
		t.Fatalf("GetAppByID(app1) after switch: %v", err)
	}
	if got1.IsDefault {
		t.Error("expected app1 to NOT be default after switching to app2")
	}

	got2, err = store.GetAppByID(ctx, app2.ID)
	if err != nil {
		t.Fatalf("GetAppByID(app2) after switch: %v", err)
	}
	if !got2.IsDefault {
		t.Error("expected app2 to be default after SetDefaultApp")
	}

	// Verify GetDefaultApp returns app2.
	def2, err := store.GetDefaultApp(ctx)
	if err != nil {
		t.Fatalf("GetDefaultApp: %v", err)
	}
	if def2 == nil {
		t.Fatal("expected a default app, got nil")
	}
	if def2.ID != app2.ID {
		t.Errorf("default app ID = %q, want %q", def2.ID, app2.ID)
	}

	// SetDefaultApp on non-existent ID returns ErrNotFound.
	err = store.SetDefaultApp(ctx, "00000000-0000-0000-0000-000000000000")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for missing app, got: %v", err)
	}

	// Cleanup.
	if err := store.DeleteApp(ctx, app1.ID); err != nil {
		t.Errorf("cleanup DeleteApp(app1): %v", err)
	}
	if err := store.DeleteApp(ctx, app2.ID); err != nil {
		t.Errorf("cleanup DeleteApp(app2): %v", err)
	}
}

func testUserCRUD(t *testing.T, store Store) {
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
	if len(users) < 1 {
		t.Errorf("ListUsers returned %d users, want >= 1", len(users))
	}
}

func testProxyTokenCRUD(t *testing.T, store Store) {
	ctx := context.Background()

	// Create a user first.
	user := &User{GitHubID: 99001, GitHubUsername: "tokenuser", Role: "user"}
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
	scopes := json.RawMessage(`{"contents":"read","pull_requests":"write"}`)
	repos := json.RawMessage(`["org/repo"]`)
	pt := &ProxyToken{
		TokenHash:     "contract_hash_001",
		TokenPrefix:   "ghx_c001",
		TokenType:     "proxy",
		UserID:        &user.ID,
		GitHubTokenID: &gt.ID,
		Repositories:  repos,
		Scopes:        scopes,
		SessionID:     "test-session",
		ExpiresAt:     timePtr(time.Now().Add(24 * time.Hour)),
	}
	if err := store.CreateProxyToken(ctx, pt); err != nil {
		t.Fatal(err)
	}

	got, err := store.GetProxyTokenByHash(ctx, "contract_hash_001")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected token, got nil")
	}
	if got.TokenType != "proxy" {
		t.Errorf("token_type = %q, want proxy", got.TokenType)
	}
	if got.TokenPrefix != "ghx_c001" {
		t.Errorf("prefix = %q, want ghx_c001", got.TokenPrefix)
	}

	var gotRepos []string
	if err := json.Unmarshal(got.Repositories, &gotRepos); err != nil {
		t.Fatal(err)
	}
	if len(gotRepos) != 1 || gotRepos[0] != "org/repo" {
		t.Errorf("repositories = %v, want [org/repo]", gotRepos)
	}

	// Test agent token.
	installID := int64(12345)
	at := &ProxyToken{
		TokenHash:      "contract_hash_002",
		TokenPrefix:    "gha_c002",
		TokenType:      "agent",
		UserID:         &user.ID,
		InstallationID: &installID,
		Repositories:   json.RawMessage(`["org/repo1","org/repo2"]`),
		Scopes:         json.RawMessage(`{"contents":"read"}`),
		SessionID:      "admin-session",
		ExpiresAt:      timePtr(time.Now().Add(365 * 24 * time.Hour)),
	}
	if err := store.CreateProxyToken(ctx, at); err != nil {
		t.Fatal(err)
	}

	gotAgent, err := store.GetProxyTokenByHash(ctx, "contract_hash_002")
	if err != nil {
		t.Fatal(err)
	}
	if gotAgent.TokenType != "agent" {
		t.Errorf("token_type = %q, want agent", gotAgent.TokenType)
	}
	if gotAgent.InstallationID == nil || *gotAgent.InstallationID != 12345 {
		t.Errorf("installation_id = %v, want 12345", gotAgent.InstallationID)
	}

	// List by user.
	tokens, err := store.ListProxyTokens(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) < 2 {
		t.Errorf("ListProxyTokens = %d, want >= 2", len(tokens))
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

func testProxyTokenWithAppID(t *testing.T, store Store) {
	ctx := context.Background()

	// Create an app.
	app := &App{
		Name:  "Token Test App",
		AppID: 55555,
	}
	if err := store.CreateApp(ctx, app); err != nil {
		t.Fatalf("CreateApp: %v", err)
	}

	// Create a user.
	user := &User{GitHubID: 99002, GitHubUsername: "appuser", Role: "user"}
	if err := store.UpsertUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	// Create an agent token with app_id.
	installID := int64(67890)
	pt := &ProxyToken{
		TokenHash:      "contract_hash_app_001",
		TokenPrefix:    "gha_app1",
		TokenType:      "agent",
		AppID:          &app.ID,
		UserID:         &user.ID,
		InstallationID: &installID,
		Repositories:   json.RawMessage(`["org/app-repo"]`),
		Scopes:         json.RawMessage(`{"contents":"write"}`),
		SessionID:      "app-session",
		ExpiresAt:      timePtr(time.Now().Add(24 * time.Hour)),
	}
	if err := store.CreateProxyToken(ctx, pt); err != nil {
		t.Fatal(err)
	}

	got, err := store.GetProxyTokenByHash(ctx, "contract_hash_app_001")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected token, got nil")
	}
	if got.AppID == nil {
		t.Fatal("expected app_id to be set")
	}
	if *got.AppID != app.ID {
		t.Errorf("app_id = %q, want %q", *got.AppID, app.ID)
	}

	// Create a token WITHOUT app_id (backward compat).
	pt2 := &ProxyToken{
		TokenHash:      "contract_hash_app_002",
		TokenPrefix:    "gha_app2",
		TokenType:      "agent",
		UserID:         &user.ID,
		InstallationID: &installID,
		Repositories:   json.RawMessage(`[]`),
		Scopes:         json.RawMessage(`{}`),
		ExpiresAt:      timePtr(time.Now().Add(24 * time.Hour)),
	}
	if err := store.CreateProxyToken(ctx, pt2); err != nil {
		t.Fatal(err)
	}
	got2, err := store.GetProxyTokenByHash(ctx, "contract_hash_app_002")
	if err != nil {
		t.Fatal(err)
	}
	if got2.AppID != nil {
		t.Errorf("expected nil app_id, got %q", *got2.AppID)
	}

	// Cleanup.
	if err := store.DeleteApp(ctx, app.ID); err != nil {
		t.Errorf("cleanup DeleteApp: %v", err)
	}
}

func testProxyTokenNoExpiry(t *testing.T, store Store) {
	ctx := context.Background()

	// Create a user for the token.
	user := &User{GitHubID: 990099, GitHubUsername: "noexpiry-user", GitHubEmail: "noexp@test.com"}
	if err := store.UpsertUser(ctx, user); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}
	gt := &GitHubToken{
		UserID:                user.ID,
		AccessToken:           "enc_noexp",
		RefreshToken:          "enc_noexp_refresh",
		AccessTokenExpiresAt:  time.Now().Add(8 * time.Hour),
		RefreshTokenExpiresAt: time.Now().Add(180 * 24 * time.Hour),
		Scopes:                "repo",
	}
	if err := store.UpsertGitHubToken(ctx, gt); err != nil {
		t.Fatalf("UpsertGitHubToken: %v", err)
	}

	// Create a no-expiry token (ExpiresAt = nil).
	pt := &ProxyToken{
		TokenHash:     "contract_hash_noexpiry",
		TokenPrefix:   "ghx_noex",
		TokenType:     "proxy",
		UserID:        &user.ID,
		GitHubTokenID: &gt.ID,
		Repositories:  json.RawMessage(`["org/repo"]`),
		Scopes:        json.RawMessage(`{"contents":"read"}`),
		SessionID:     "no-expiry-session",
		ExpiresAt:     nil,
	}
	if err := store.CreateProxyToken(ctx, pt); err != nil {
		t.Fatalf("CreateProxyToken (no expiry): %v", err)
	}

	// Retrieve by hash and verify ExpiresAt is nil.
	got, err := store.GetProxyTokenByHash(ctx, "contract_hash_noexpiry")
	if err != nil {
		t.Fatalf("GetProxyTokenByHash: %v", err)
	}
	if got == nil {
		t.Fatal("expected token, got nil")
	}
	if got.ExpiresAt != nil {
		t.Fatalf("expected nil ExpiresAt for no-expiry token, got %v", got.ExpiresAt)
	}

	// Retrieve by ID and verify.
	gotByID, err := store.GetProxyTokenByID(ctx, pt.ID)
	if err != nil {
		t.Fatalf("GetProxyTokenByID: %v", err)
	}
	if gotByID.ExpiresAt != nil {
		t.Fatalf("expected nil ExpiresAt for no-expiry token (by ID), got %v", gotByID.ExpiresAt)
	}

	// No-expiry tokens should appear in the active list.
	active, err := store.ListActiveProxyTokens(ctx)
	if err != nil {
		t.Fatalf("ListActiveProxyTokens: %v", err)
	}
	found := false
	for _, a := range active {
		if a.ID == pt.ID {
			found = true
			break
		}
	}
	if !found {
		t.Error("no-expiry token should appear in active tokens list")
	}
}

func testUpdateProxyTokenAppID(t *testing.T, store Store) {
	ctx := context.Background()

	// Create an app to use as the target.
	app := &App{
		Name:  "Update AppID Test App",
		AppID: 77777,
	}
	if err := store.CreateApp(ctx, app); err != nil {
		t.Fatalf("CreateApp: %v", err)
	}

	// Create a user.
	user := &User{GitHubID: 99003, GitHubUsername: "backfilluser", Role: "user"}
	if err := store.UpsertUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	// Create an agent token WITHOUT app_id (simulates pre-multi-app token).
	installID := int64(11111)
	pt := &ProxyToken{
		TokenHash:      "contract_hash_backfill_001",
		TokenPrefix:    "gha_bf1",
		TokenType:      "agent",
		UserID:         &user.ID,
		InstallationID: &installID,
		Repositories:   json.RawMessage(`[]`),
		Scopes:         json.RawMessage(`{}`),
		ExpiresAt:      timePtr(time.Now().Add(24 * time.Hour)),
	}
	if err := store.CreateProxyToken(ctx, pt); err != nil {
		t.Fatal(err)
	}

	// Verify app_id is nil before update.
	got, err := store.GetProxyTokenByHash(ctx, "contract_hash_backfill_001")
	if err != nil {
		t.Fatal(err)
	}
	if got.AppID != nil {
		t.Fatalf("expected nil app_id before update, got %q", *got.AppID)
	}

	// Update app_id.
	if err := store.UpdateProxyTokenAppID(ctx, got.ID, app.ID); err != nil {
		t.Fatal(err)
	}

	// Verify app_id is set after update.
	got2, err := store.GetProxyTokenByHash(ctx, "contract_hash_backfill_001")
	if err != nil {
		t.Fatal(err)
	}
	if got2.AppID == nil {
		t.Fatal("expected app_id to be set after update")
	}
	if *got2.AppID != app.ID {
		t.Errorf("app_id = %q, want %q", *got2.AppID, app.ID)
	}

	// Verify ErrNotFound for nonexistent token.
	err = store.UpdateProxyTokenAppID(ctx, "00000000-0000-0000-0000-000000000000", app.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for missing token, got: %v", err)
	}

	// Cleanup.
	if err := store.DeleteApp(ctx, app.ID); err != nil {
		t.Errorf("cleanup DeleteApp: %v", err)
	}
}

func testUpdateProxyTokenScopes(t *testing.T, store Store) {
	ctx := context.Background()

	user := &User{GitHubID: 99099, GitHubUsername: "scopeuser", Role: "user"}
	if err := store.UpsertUser(ctx, user); err != nil {
		t.Fatal(err)
	}

	pt := &ProxyToken{
		TokenHash:    "contract_hash_scopes_001",
		TokenPrefix:  "ghx_sc1",
		TokenType:    "proxy",
		UserID:       &user.ID,
		Repositories: json.RawMessage(`["org/repo1"]`),
		Scopes:       json.RawMessage(`{"contents":"read"}`),
		ExpiresAt:    timePtr(time.Now().Add(24 * time.Hour)),
	}
	if err := store.CreateProxyToken(ctx, pt); err != nil {
		t.Fatalf("CreateProxyToken: %v", err)
	}

	newRepos := json.RawMessage(`["org/repo1","org/repo2"]`)
	newScopes := json.RawMessage(`{"contents":"write","pull_requests":"read"}`)
	if err := store.UpdateProxyTokenScopes(ctx, pt.ID, newRepos, newScopes); err != nil {
		t.Fatalf("UpdateProxyTokenScopes: %v", err)
	}

	got, err := store.GetProxyTokenByHash(ctx, "contract_hash_scopes_001")
	if err != nil {
		t.Fatal(err)
	}

	var gotRepos []string
	if err := json.Unmarshal(got.Repositories, &gotRepos); err != nil {
		t.Fatalf("unmarshal repositories: %v", err)
	}
	if len(gotRepos) != 2 || gotRepos[0] != "org/repo1" || gotRepos[1] != "org/repo2" {
		t.Errorf("repositories = %v, want [org/repo1 org/repo2]", gotRepos)
	}

	var gotScopes map[string]string
	if err := json.Unmarshal(got.Scopes, &gotScopes); err != nil {
		t.Fatalf("unmarshal scopes: %v", err)
	}
	if gotScopes["contents"] != "write" {
		t.Errorf("scopes[contents] = %q, want write", gotScopes["contents"])
	}
	if gotScopes["pull_requests"] != "read" {
		t.Errorf("scopes[pull_requests] = %q, want read", gotScopes["pull_requests"])
	}

	// Clear to open-scoped (empty arrays/objects).
	if err := store.UpdateProxyTokenScopes(ctx, pt.ID, json.RawMessage(`[]`), json.RawMessage(`{}`)); err != nil {
		t.Fatalf("UpdateProxyTokenScopes (clear): %v", err)
	}
	got2, err := store.GetProxyTokenByHash(ctx, "contract_hash_scopes_001")
	if err != nil {
		t.Fatal(err)
	}
	var clearedRepos []string
	if err := json.Unmarshal(got2.Repositories, &clearedRepos); err != nil {
		t.Fatalf("unmarshal cleared repositories: %v", err)
	}
	if len(clearedRepos) != 0 {
		t.Errorf("expected empty repositories after clear, got %v", clearedRepos)
	}
	var clearedScopes map[string]string
	if err := json.Unmarshal(got2.Scopes, &clearedScopes); err != nil {
		t.Fatalf("unmarshal cleared scopes: %v", err)
	}
	if len(clearedScopes) != 0 {
		t.Errorf("expected empty scopes after clear, got %v", clearedScopes)
	}

	// ErrNotFound for missing token.
	err = store.UpdateProxyTokenScopes(ctx, "00000000-0000-0000-0000-000000000000", newRepos, newScopes)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for missing token, got: %v", err)
	}
}

func testGitHubTokenAppID(t *testing.T, store Store) {
	ctx := context.Background()

	// Create an app to associate with the token.
	app := &App{Name: "GitHubToken App", AppID: 77777}
	if err := store.CreateApp(ctx, app); err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	defer store.DeleteApp(ctx, app.ID)

	// Create a user.
	user := &User{GitHubID: 99003, GitHubUsername: "ghtokenuser", Role: "user"}
	if err := store.UpsertUser(ctx, user); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	// Upsert a GitHub token with AppID set.
	gt := &GitHubToken{
		UserID:                user.ID,
		AppID:                 &app.ID,
		AccessToken:           "enc_access_appid",
		RefreshToken:          "enc_refresh_appid",
		AccessTokenExpiresAt:  time.Now().Add(8 * time.Hour),
		RefreshTokenExpiresAt: time.Now().Add(180 * 24 * time.Hour),
		Scopes:                "repo",
	}
	if err := store.UpsertGitHubToken(ctx, gt); err != nil {
		t.Fatalf("UpsertGitHubToken with AppID: %v", err)
	}

	// Round-trip via GetGitHubToken.
	got, err := store.GetGitHubToken(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetGitHubToken: %v", err)
	}
	if got == nil {
		t.Fatal("expected token, got nil")
	}
	if got.AppID == nil {
		t.Fatal("expected AppID to be set after round-trip")
	}
	if *got.AppID != app.ID {
		t.Errorf("AppID = %q, want %q", *got.AppID, app.ID)
	}

	// Round-trip via GetGitHubTokenByID.
	got2, err := store.GetGitHubTokenByID(ctx, gt.ID)
	if err != nil {
		t.Fatalf("GetGitHubTokenByID: %v", err)
	}
	if got2 == nil {
		t.Fatal("expected token by ID, got nil")
	}
	if got2.AppID == nil {
		t.Fatal("expected AppID to be set in GetGitHubTokenByID result")
	}
	if *got2.AppID != app.ID {
		t.Errorf("GetGitHubTokenByID AppID = %q, want %q", *got2.AppID, app.ID)
	}

	// Verify nil AppID is preserved for tokens without an app association.
	user2 := &User{GitHubID: 99004, GitHubUsername: "ghtokenuser2", Role: "user"}
	if err := store.UpsertUser(ctx, user2); err != nil {
		t.Fatalf("UpsertUser2: %v", err)
	}
	gt2 := &GitHubToken{
		UserID:                user2.ID,
		AccessToken:           "enc_access_noapp",
		RefreshToken:          "enc_refresh_noapp",
		AccessTokenExpiresAt:  time.Now().Add(8 * time.Hour),
		RefreshTokenExpiresAt: time.Now().Add(180 * 24 * time.Hour),
	}
	if err := store.UpsertGitHubToken(ctx, gt2); err != nil {
		t.Fatalf("UpsertGitHubToken without AppID: %v", err)
	}
	got3, err := store.GetGitHubToken(ctx, user2.ID)
	if err != nil {
		t.Fatalf("GetGitHubToken (no app): %v", err)
	}
	if got3 == nil {
		t.Fatal("expected token, got nil")
	}
	if got3.AppID != nil {
		t.Errorf("expected nil AppID for token without app, got %q", *got3.AppID)
	}
}

func testCachedRepositoryCRUD(t *testing.T, store Store) {
	ctx := context.Background()

	// Create.
	repo := &CachedRepository{
		Owner:   "myorg",
		Name:    "myrepo",
		Enabled: true,
	}
	if err := store.CreateCachedRepository(ctx, repo); err != nil {
		t.Fatalf("CreateCachedRepository: %v", err)
	}
	if repo.ID == "" {
		t.Fatal("expected ID to be set")
	}
	if repo.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be set")
	}
	if repo.UpdatedAt.IsZero() {
		t.Fatal("expected UpdatedAt to be set")
	}

	// Get by ID.
	got, err := store.GetCachedRepositoryByID(ctx, repo.ID)
	if err != nil {
		t.Fatalf("GetCachedRepositoryByID: %v", err)
	}
	if got == nil {
		t.Fatal("expected repo, got nil")
	}
	if got.Owner != "myorg" {
		t.Errorf("owner = %q, want myorg", got.Owner)
	}
	if got.Name != "myrepo" {
		t.Errorf("name = %q, want myrepo", got.Name)
	}
	if !got.Enabled {
		t.Error("expected enabled = true")
	}
	if got.TimeoutSeconds != nil {
		t.Errorf("expected nil TimeoutSeconds, got %d", *got.TimeoutSeconds)
	}
	if got.MaxCacheSizeMB != nil {
		t.Errorf("expected nil MaxCacheSizeMB, got %d", *got.MaxCacheSizeMB)
	}
	if got.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set on retrieved repo")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("expected UpdatedAt to be set on retrieved repo")
	}

	// Get by owner/name.
	got2, err := store.GetCachedRepositoryByOwnerName(ctx, "myorg", "myrepo")
	if err != nil {
		t.Fatalf("GetCachedRepositoryByOwnerName: %v", err)
	}
	if got2 == nil {
		t.Fatal("expected repo by owner/name, got nil")
	}
	if got2.ID != repo.ID {
		t.Errorf("ID = %q, want %q", got2.ID, repo.ID)
	}

	// Get by owner/name — not found.
	got3, err := store.GetCachedRepositoryByOwnerName(ctx, "myorg", "nonexistent")
	if err != nil {
		t.Fatalf("GetCachedRepositoryByOwnerName (missing): %v", err)
	}
	if got3 != nil {
		t.Errorf("expected nil for missing repo, got %+v", got3)
	}

	// List.
	repos, err := store.ListCachedRepositories(ctx)
	if err != nil {
		t.Fatalf("ListCachedRepositories: %v", err)
	}
	if len(repos) < 1 {
		t.Errorf("ListCachedRepositories returned %d, want >= 1", len(repos))
	}

	// Update — disable.
	repo.Enabled = false
	if err := store.UpdateCachedRepository(ctx, repo); err != nil {
		t.Fatalf("UpdateCachedRepository: %v", err)
	}
	got4, err := store.GetCachedRepositoryByID(ctx, repo.ID)
	if err != nil {
		t.Fatalf("GetCachedRepositoryByID after update: %v", err)
	}
	if got4.Enabled {
		t.Error("expected enabled = false after update")
	}
	if got4.CreatedAt.IsZero() {
		t.Error("expected CreatedAt preserved after update")
	}
	if got4.UpdatedAt.IsZero() {
		t.Error("expected UpdatedAt set after update")
	}

	// Update — set timeout.
	timeout := 600
	repo.TimeoutSeconds = &timeout
	if err := store.UpdateCachedRepository(ctx, repo); err != nil {
		t.Fatalf("UpdateCachedRepository (timeout): %v", err)
	}
	got4b, err := store.GetCachedRepositoryByID(ctx, repo.ID)
	if err != nil {
		t.Fatalf("GetCachedRepositoryByID after timeout update: %v", err)
	}
	if got4b.TimeoutSeconds == nil || *got4b.TimeoutSeconds != 600 {
		t.Errorf("TimeoutSeconds = %v, want 600", got4b.TimeoutSeconds)
	}

	// Update — set max cache size.
	maxSize := 100
	repo.MaxCacheSizeMB = &maxSize
	if err := store.UpdateCachedRepository(ctx, repo); err != nil {
		t.Fatalf("UpdateCachedRepository (max_cache_size): %v", err)
	}
	got4c, err := store.GetCachedRepositoryByID(ctx, repo.ID)
	if err != nil {
		t.Fatalf("GetCachedRepositoryByID after max_cache_size update: %v", err)
	}
	if got4c.MaxCacheSizeMB == nil || *got4c.MaxCacheSizeMB != 100 {
		t.Errorf("MaxCacheSizeMB = %v, want 100", got4c.MaxCacheSizeMB)
	}

	// Update — clear max cache size.
	repo.MaxCacheSizeMB = nil
	if err := store.UpdateCachedRepository(ctx, repo); err != nil {
		t.Fatalf("UpdateCachedRepository (clear max_cache_size): %v", err)
	}
	got4d, err := store.GetCachedRepositoryByID(ctx, repo.ID)
	if err != nil {
		t.Fatalf("GetCachedRepositoryByID after clearing max_cache_size: %v", err)
	}
	if got4d.MaxCacheSizeMB != nil {
		t.Errorf("expected nil MaxCacheSizeMB after clearing, got %d", *got4d.MaxCacheSizeMB)
	}

	// Update non-existent should return ErrNotFound.
	err = store.UpdateCachedRepository(ctx, &CachedRepository{
		ID:    "00000000-0000-0000-0000-000000000000",
		Owner: "x",
		Name:  "y",
	})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound updating non-existent repo, got: %v", err)
	}

	// Create a second repo with timeout and max cache size set.
	timeout2 := 120
	maxSize2 := 500
	repo2 := &CachedRepository{
		Owner:          "otherorg",
		Name:           "otherrepo",
		Enabled:        true,
		TimeoutSeconds: &timeout2,
		MaxCacheSizeMB: &maxSize2,
	}
	if err := store.CreateCachedRepository(ctx, repo2); err != nil {
		t.Fatalf("CreateCachedRepository (second): %v", err)
	}
	got7, err := store.GetCachedRepositoryByID(ctx, repo2.ID)
	if err != nil {
		t.Fatalf("GetCachedRepositoryByID (second): %v", err)
	}
	if got7.TimeoutSeconds == nil || *got7.TimeoutSeconds != 120 {
		t.Errorf("second repo TimeoutSeconds = %v, want 120", got7.TimeoutSeconds)
	}
	if got7.MaxCacheSizeMB == nil || *got7.MaxCacheSizeMB != 500 {
		t.Errorf("second repo MaxCacheSizeMB = %v, want 500", got7.MaxCacheSizeMB)
	}

	repos2, err := store.ListCachedRepositories(ctx)
	if err != nil {
		t.Fatalf("ListCachedRepositories: %v", err)
	}
	if len(repos2) < 2 {
		t.Errorf("ListCachedRepositories returned %d, want >= 2", len(repos2))
	}

	// Delete.
	if err := store.DeleteCachedRepository(ctx, repo.ID); err != nil {
		t.Fatalf("DeleteCachedRepository: %v", err)
	}
	got5, err := store.GetCachedRepositoryByID(ctx, repo.ID)
	if err != nil {
		t.Fatalf("GetCachedRepositoryByID after delete: %v", err)
	}
	if got5 != nil {
		t.Error("expected nil after delete")
	}

	// Verify owner/name index is cleaned up after delete.
	got6, err := store.GetCachedRepositoryByOwnerName(ctx, "myorg", "myrepo")
	if err != nil {
		t.Fatalf("GetCachedRepositoryByOwnerName after delete: %v", err)
	}
	if got6 != nil {
		t.Error("expected nil from owner/name lookup after delete")
	}

	// Delete non-existent returns ErrNotFound.
	if err := store.DeleteCachedRepository(ctx, "00000000-0000-0000-0000-000000000000"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound deleting non-existent repo, got: %v", err)
	}

	// Cleanup second repo.
	if err := store.DeleteCachedRepository(ctx, repo2.ID); err != nil {
		t.Errorf("cleanup DeleteCachedRepository (second): %v", err)
	}
}

func testSyncAdminRoles(t *testing.T, store Store) {
	ctx := context.Background()

	u1 := &User{GitHubID: 99101, GitHubUsername: "syncalice", Role: "user"}
	u2 := &User{GitHubID: 99102, GitHubUsername: "syncbob", Role: "user"}
	if err := store.UpsertUser(ctx, u1); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertUser(ctx, u2); err != nil {
		t.Fatal(err)
	}

	// Promote syncalice.
	if err := store.SyncAdminRoles(ctx, []string{"syncalice"}); err != nil {
		t.Fatalf("SyncAdminRoles: %v", err)
	}
	got, _ := store.GetUserByGitHubID(ctx, 99101)
	if got.Role != "admin" {
		t.Errorf("syncalice role = %q, want admin", got.Role)
	}
	got2, _ := store.GetUserByGitHubID(ctx, 99102)
	if got2.Role != "user" {
		t.Errorf("syncbob role = %q, want user", got2.Role)
	}

	// Demote.
	if err := store.SyncAdminRoles(ctx, []string{}); err != nil {
		t.Fatalf("SyncAdminRoles (empty): %v", err)
	}
	got3, _ := store.GetUserByGitHubID(ctx, 99101)
	if got3.Role != "user" {
		t.Errorf("syncalice role after demotion = %q, want user", got3.Role)
	}
}

func testDeleteExpiredProxyTokens(t *testing.T, store Store) {
	ctx := context.Background()

	user := &User{GitHubID: 98001, GitHubUsername: "cleanup-user", Role: "user"}
	if err := store.UpsertUser(ctx, user); err != nil {
		t.Fatalf("UpsertUser: %v", err)
	}

	// Create a token that expired 2 days ago.  Use UTC throughout so the
	// contract test does not depend on the process timezone.
	expiredToken := &ProxyToken{
		TokenHash:    "cleanup_hash_expired",
		TokenPrefix:  "ghx_cleanup_exp",
		TokenType:    "proxy",
		UserID:       &user.ID,
		Repositories: json.RawMessage(`[]`),
		Scopes:       json.RawMessage(`{}`),
		SessionID:    "cleanup-session-1",
		ExpiresAt:    timePtr(time.Now().UTC().Add(-48 * time.Hour)),
	}
	if err := store.CreateProxyToken(ctx, expiredToken); err != nil {
		t.Fatalf("CreateProxyToken (expired): %v", err)
	}

	// Create a token that is revoked "just now" (still within expiry) — its
	// revoked_at will be inside the 1-hour retention window used below, so it
	// must survive the cleanup call.
	revokedToken := &ProxyToken{
		TokenHash:    "cleanup_hash_revoked",
		TokenPrefix:  "ghx_cleanup_rev",
		TokenType:    "proxy",
		UserID:       &user.ID,
		Repositories: json.RawMessage(`[]`),
		Scopes:       json.RawMessage(`{}`),
		SessionID:    "cleanup-session-2",
		ExpiresAt:    timePtr(time.Now().UTC().Add(24 * time.Hour)),
	}
	if err := store.CreateProxyToken(ctx, revokedToken); err != nil {
		t.Fatalf("CreateProxyToken (to-be-revoked): %v", err)
	}
	if err := store.RevokeProxyToken(ctx, revokedToken.ID); err != nil {
		t.Fatalf("RevokeProxyToken: %v", err)
	}
	// revokedToken.RevokedAt is set to "just now", which is within the 1-hour
	// retention window used below — so it must survive the cleanup call.

	// Create an active (non-expired, non-revoked) token that must be preserved.
	activeToken := &ProxyToken{
		TokenHash:    "cleanup_hash_active",
		TokenPrefix:  "ghx_cleanup_act",
		TokenType:    "proxy",
		UserID:       &user.ID,
		Repositories: json.RawMessage(`[]`),
		Scopes:       json.RawMessage(`{}`),
		SessionID:    "cleanup-session-3",
		ExpiresAt:    timePtr(time.Now().UTC().Add(24 * time.Hour)),
	}
	if err := store.CreateProxyToken(ctx, activeToken); err != nil {
		t.Fatalf("CreateProxyToken (active): %v", err)
	}

	// Create a no-expiry token that is NOT revoked — must be preserved.
	noExpiryToken := &ProxyToken{
		TokenHash:    "cleanup_hash_noexp",
		TokenPrefix:  "ghx_cleanup_noe",
		TokenType:    "proxy",
		UserID:       &user.ID,
		Repositories: json.RawMessage(`[]`),
		Scopes:       json.RawMessage(`{}`),
		SessionID:    "cleanup-session-4",
		ExpiresAt:    nil,
	}
	if err := store.CreateProxyToken(ctx, noExpiryToken); err != nil {
		t.Fatalf("CreateProxyToken (no-expiry): %v", err)
	}

	// Create a no-expiry token that WAS revoked 2 hours ago — must be deleted.
	// The documented behaviour is: "Tokens with no expiry (expires_at IS NULL)
	// are only deleted when they have been revoked."  We set revoked_at to a
	// past value via a backend-specific helper because RevokeProxyToken always
	// uses NOW().
	noExpiryRevokedToken := &ProxyToken{
		TokenHash:    "cleanup_hash_noexp_rev",
		TokenPrefix:  "ghx_cleanup_ner",
		TokenType:    "proxy",
		UserID:       &user.ID,
		Repositories: json.RawMessage(`[]`),
		Scopes:       json.RawMessage(`{}`),
		SessionID:    "cleanup-session-5",
		ExpiresAt:    nil,
	}
	if err := store.CreateProxyToken(ctx, noExpiryRevokedToken); err != nil {
		t.Fatalf("CreateProxyToken (no-expiry revoked): %v", err)
	}
	pastRevocation := time.Now().UTC().Add(-2 * time.Hour)
	switch s := store.(type) {
	case *SQLiteStore:
		if _, err := s.db.ExecContext(ctx,
			"UPDATE proxy_tokens SET revoked_at = ? WHERE id = ?",
			pastRevocation, noExpiryRevokedToken.ID); err != nil {
			t.Fatalf("setRevokedAt (SQLite): %v", err)
		}
	case *PostgresStore:
		if _, err := s.db.ExecContext(ctx,
			"UPDATE proxy_tokens SET revoked_at = $1 WHERE id = $2",
			pastRevocation, noExpiryRevokedToken.ID); err != nil {
			t.Fatalf("setRevokedAt (Postgres): %v", err)
		}
	case *VaultStore:
		tok, err := s.GetProxyTokenByID(ctx, noExpiryRevokedToken.ID)
		if err != nil || tok == nil {
			t.Fatalf("GetProxyTokenByID (for setRevokedAt): %v", err)
		}
		tok.RevokedAt = &pastRevocation
		if err := s.writeProxyToken(ctx, tok); err != nil {
			t.Fatalf("writeProxyToken (set past revokedAt): %v", err)
		}
	default:
		t.Skipf("no-expiry+revoked test skipped: unsupported backend %T", store)
	}

	// With a retention period of 1 hour: the expired token (48h old) and the
	// no-expiry revoked token (revoked 2h ago) should both be deleted (n==2).
	// The recently-revoked token survives (revoked_at within the last hour).
	// The active and unrevoked no-expiry tokens are never deleted.
	n, err := store.DeleteExpiredProxyTokens(ctx, time.Hour)
	if err != nil {
		t.Fatalf("DeleteExpiredProxyTokens: %v", err)
	}
	if n != 2 {
		t.Errorf("expected exactly 2 tokens deleted, got %d", n)
	}

	// Expired token must be gone.
	gone, err := store.GetProxyTokenByID(ctx, expiredToken.ID)
	if err != nil {
		t.Fatalf("GetProxyTokenByID (expired, post-cleanup): %v", err)
	}
	if gone != nil {
		t.Error("expected expired token to be hard-deleted, but it still exists")
	}

	// Recently-revoked token must still exist: its revoked_at is within the
	// 1-hour retention window so it is not yet eligible for hard-delete.
	stillRevoked, err := store.GetProxyTokenByID(ctx, revokedToken.ID)
	if err != nil {
		t.Fatalf("GetProxyTokenByID (revoked, post-cleanup): %v", err)
	}
	if stillRevoked == nil {
		t.Error("expected recently-revoked token to survive cleanup (within retention window)")
	}

	// Active token must still exist.
	still, err := store.GetProxyTokenByID(ctx, activeToken.ID)
	if err != nil {
		t.Fatalf("GetProxyTokenByID (active, post-cleanup): %v", err)
	}
	if still == nil {
		t.Error("expected active token to be preserved after cleanup")
	}

	// No-expiry token (unrevoked) must still exist.
	stillNoExp, err := store.GetProxyTokenByID(ctx, noExpiryToken.ID)
	if err != nil {
		t.Fatalf("GetProxyTokenByID (no-expiry, post-cleanup): %v", err)
	}
	if stillNoExp == nil {
		t.Error("expected no-expiry token to be preserved after cleanup")
	}

	// No-expiry + old-revocation token must be gone: expires_at IS NULL tokens
	// are eligible for deletion when revoked_at is beyond the retention window.
	goneNoExpRev, err := store.GetProxyTokenByID(ctx, noExpiryRevokedToken.ID)
	if err != nil {
		t.Fatalf("GetProxyTokenByID (no-expiry revoked, post-cleanup): %v", err)
	}
	if goneNoExpRev != nil {
		t.Error("expected no-expiry revoked token (revoked 2h ago) to be hard-deleted, but it still exists")
	}

	// Calling DeleteExpiredProxyTokens again must be idempotent: the expired
	// and no-expiry-revoked tokens were already removed, the recently-revoked
	// token is still within the 1-hour window, and the active/no-expiry tokens
	// are never eligible — so zero
	// additional rows should be deleted.
	n2, err := store.DeleteExpiredProxyTokens(ctx, time.Hour)
	if err != nil {
		t.Fatalf("DeleteExpiredProxyTokens (idempotent): %v", err)
	}
	if n2 != 0 {
		t.Errorf("expected 0 deletions on second call (idempotent), got %d", n2)
	}
}

func testSessionCRUD(t *testing.T, store Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	sess := &Session{
		TokenHash: "session-hash-aaa",
		UserID:    "user-1",
		Username:  "alice",
		Role:      "user",
		ExpiresAt: now.Add(time.Hour),
	}
	if err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	got, err := store.GetSessionByTokenHash(ctx, sess.TokenHash)
	if err != nil {
		t.Fatalf("GetSessionByTokenHash: %v", err)
	}
	if got.UserID != sess.UserID || got.Username != sess.Username || got.Role != sess.Role {
		t.Errorf("session round-trip mismatch: got %+v, want %+v", got, sess)
	}
	if got.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set on retrieved session")
	}

	// Lookup with an unknown hash must return wrapped ErrNotFound. Use a
	// non-empty hash to exercise the not-found path rather than the empty
	// guard.
	_, err = store.GetSessionByTokenHash(ctx, "unknown-hash-xxx")
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for unknown session, got: %v", err)
	}

	// Expired sessions are also not found.
	expired := &Session{
		TokenHash: "session-hash-expired",
		UserID:    "user-2",
		Username:  "bob",
		Role:      "user",
		ExpiresAt: now.Add(-time.Minute),
	}
	if err := store.CreateSession(ctx, expired); err != nil {
		t.Fatalf("CreateSession (expired): %v", err)
	}
	_, err = store.GetSessionByTokenHash(ctx, expired.TokenHash)
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for expired session, got: %v", err)
	}

	// Cleanup removes the expired row.
	n, err := store.DeleteExpiredSessions(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredSessions: %v", err)
	}
	if n < 1 {
		t.Errorf("DeleteExpiredSessions removed %d rows, want >= 1", n)
	}

	// Active session is preserved.
	if _, err := store.GetSessionByTokenHash(ctx, sess.TokenHash); err != nil {
		t.Errorf("active session should survive cleanup: %v", err)
	}

	// Explicit delete is idempotent (no-op for missing rows).
	if err := store.DeleteSession(ctx, sess.TokenHash); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if err := store.DeleteSession(ctx, sess.TokenHash); err != nil {
		t.Errorf("DeleteSession on missing row should be a no-op: %v", err)
	}
	_, err = store.GetSessionByTokenHash(ctx, sess.TokenHash)
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got: %v", err)
	}
}

func testOAuthStateConsume(t *testing.T, store Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	// Login state: round-trip ReturnTo.
	if err := store.CreateOAuthState(ctx, &OAuthState{
		State:     "login-state-123",
		Kind:      OAuthStateKindLogin,
		ReturnTo:  "/cli/auth?user_code=ABCD-EFGH",
		ExpiresAt: now.Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("CreateOAuthState (login): %v", err)
	}

	got, err := store.ConsumeOAuthState(ctx, "login-state-123", OAuthStateKindLogin)
	if err != nil {
		t.Fatalf("ConsumeOAuthState (login): %v", err)
	}
	if got.ReturnTo != "/cli/auth?user_code=ABCD-EFGH" {
		t.Errorf("ReturnTo round-trip: got %q", got.ReturnTo)
	}
	if got.Kind != OAuthStateKindLogin {
		t.Errorf("Kind = %q, want login", got.Kind)
	}

	// Consume must be one-shot: a second consume of the same state returns
	// ErrNotFound.
	_, err = store.ConsumeOAuthState(ctx, "login-state-123", OAuthStateKindLogin)
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound on second consume, got: %v", err)
	}

	// Wrong-kind consume of a present state must also return ErrNotFound.
	if err := store.CreateOAuthState(ctx, &OAuthState{
		State:                 "broker-state-456",
		Kind:                  OAuthStateKindBroker,
		BrokerRedirectURI:     "https://app.example.com/cb",
		BrokerDownstreamState: "csrf-789",
		ExpiresAt:             now.Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("CreateOAuthState (broker): %v", err)
	}
	_, err = store.ConsumeOAuthState(ctx, "broker-state-456", OAuthStateKindLogin)
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for wrong-kind consume, got: %v", err)
	}

	// The broker state itself must round-trip correctly.
	bs, err := store.ConsumeOAuthState(ctx, "broker-state-456", OAuthStateKindBroker)
	if err != nil {
		t.Fatalf("ConsumeOAuthState (broker): %v", err)
	}
	if bs.BrokerRedirectURI != "https://app.example.com/cb" {
		t.Errorf("BrokerRedirectURI round-trip: got %q", bs.BrokerRedirectURI)
	}
	if bs.BrokerDownstreamState != "csrf-789" {
		t.Errorf("BrokerDownstreamState round-trip: got %q", bs.BrokerDownstreamState)
	}

	// Expired state is not returned and is cleaned up.
	if err := store.CreateOAuthState(ctx, &OAuthState{
		State:     "expired-state",
		Kind:      OAuthStateKindLogin,
		ExpiresAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("CreateOAuthState (expired): %v", err)
	}
	_, err = store.ConsumeOAuthState(ctx, "expired-state", OAuthStateKindLogin)
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for expired state, got: %v", err)
	}

	if _, err := store.DeleteExpiredOAuthStates(ctx); err != nil {
		t.Fatalf("DeleteExpiredOAuthStates: %v", err)
	}

	// Lookup of a never-issued state is ErrNotFound.
	_, err = store.ConsumeOAuthState(ctx, "never-existed", OAuthStateKindLogin)
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for unknown state, got: %v", err)
	}

	// Concurrent consume race: many goroutines hammer the same state and
	// exactly one must observe it; the rest must see ErrNotFound. Without
	// atomic read-and-delete (e.g. the prior SELECT-then-DELETE on
	// SQLite), a snapshot-isolation race could let two callers both read
	// the row and "consume" it, allowing replay.
	if err := store.CreateOAuthState(ctx, &OAuthState{
		State:     "race-state",
		Kind:      OAuthStateKindLogin,
		ReturnTo:  "/race",
		ExpiresAt: now.Add(10 * time.Minute),
	}); err != nil {
		t.Fatalf("CreateOAuthState (race): %v", err)
	}
	const racers = 16
	var wg sync.WaitGroup
	wg.Add(racers)
	results := make(chan error, racers)
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		go func() {
			defer wg.Done()
			<-start
			_, err := store.ConsumeOAuthState(ctx, "race-state", OAuthStateKindLogin)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	winners, notFound, otherErrs := 0, 0, 0
	for err := range results {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, ErrNotFound):
			notFound++
		default:
			otherErrs++
			t.Errorf("unexpected error from concurrent ConsumeOAuthState: %v", err)
		}
	}
	if winners != 1 {
		t.Errorf("concurrent consume: %d winners, want exactly 1 (notFound=%d, errs=%d)", winners, notFound, otherErrs)
	}
}

func testDeviceAuthCRUD(t *testing.T, store Store) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	da := &DeviceAuth{
		DeviceCode: "device-code-aaaa",
		UserCode:   "AAAA-BBBB",
		Status:     DeviceAuthStatusPending,
		ExpiresAt:  now.Add(10 * time.Minute),
	}
	if err := store.CreateDeviceAuth(ctx, da); err != nil {
		t.Fatalf("CreateDeviceAuth: %v", err)
	}

	// Lookup by device_code.
	got, err := store.GetDeviceAuthByDeviceCode(ctx, da.DeviceCode)
	if err != nil {
		t.Fatalf("GetDeviceAuthByDeviceCode: %v", err)
	}
	if got.UserCode != da.UserCode || got.Status != da.Status {
		t.Errorf("round-trip mismatch: got %+v", got)
	}

	// Lookup by user_code.
	got2, err := store.GetDeviceAuthByUserCode(ctx, da.UserCode)
	if err != nil {
		t.Fatalf("GetDeviceAuthByUserCode: %v", err)
	}
	if got2.DeviceCode != da.DeviceCode {
		t.Errorf("user_code -> device_code resolve mismatch: got %q", got2.DeviceCode)
	}

	// Update to approved with session token + last_polled_at.
	polled := now.Add(-time.Second)
	got.Status = DeviceAuthStatusApproved
	got.SessionToken = "ghpr_xxx"
	got.Username = "alice"
	got.LastPolledAt = &polled
	if err := store.UpdateDeviceAuth(ctx, got); err != nil {
		t.Fatalf("UpdateDeviceAuth: %v", err)
	}

	got3, err := store.GetDeviceAuthByDeviceCode(ctx, da.DeviceCode)
	if err != nil {
		t.Fatalf("GetDeviceAuthByDeviceCode (post-update): %v", err)
	}
	if got3.Status != DeviceAuthStatusApproved {
		t.Errorf("status after update = %q, want approved", got3.Status)
	}
	if got3.SessionToken != "ghpr_xxx" {
		t.Errorf("session_token round-trip: got %q", got3.SessionToken)
	}
	if got3.Username != "alice" {
		t.Errorf("username round-trip: got %q", got3.Username)
	}
	if got3.LastPolledAt == nil || !got3.LastPolledAt.Equal(polled) {
		t.Errorf("LastPolledAt round-trip: got %v, want %v", got3.LastPolledAt, polled)
	}

	// Update of unknown device_code returns ErrNotFound.
	missing := &DeviceAuth{
		DeviceCode: "nonexistent-device-code",
		UserCode:   "ZZZZ-ZZZZ",
		Status:     DeviceAuthStatusPending,
		ExpiresAt:  now.Add(time.Minute),
	}
	if err := store.UpdateDeviceAuth(ctx, missing); err == nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateDeviceAuth on missing row: got %v, want ErrNotFound", err)
	}

	// Duplicate user_code is rejected.
	dupe := &DeviceAuth{
		DeviceCode: "device-code-bbbb",
		UserCode:   da.UserCode,
		Status:     DeviceAuthStatusPending,
		ExpiresAt:  now.Add(10 * time.Minute),
	}
	if err := store.CreateDeviceAuth(ctx, dupe); err == nil {
		t.Error("expected error for duplicate user_code, got nil")
	}

	// Delete is idempotent.
	if err := store.DeleteDeviceAuth(ctx, da.DeviceCode); err != nil {
		t.Fatalf("DeleteDeviceAuth: %v", err)
	}
	if err := store.DeleteDeviceAuth(ctx, da.DeviceCode); err != nil {
		t.Errorf("DeleteDeviceAuth on missing row should be a no-op: %v", err)
	}
	_, err = store.GetDeviceAuthByDeviceCode(ctx, da.DeviceCode)
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound after delete, got: %v", err)
	}

	// Expired records are filtered out and cleaned up.
	if err := store.CreateDeviceAuth(ctx, &DeviceAuth{
		DeviceCode: "device-code-expired",
		UserCode:   "EXPI-RED1",
		Status:     DeviceAuthStatusPending,
		ExpiresAt:  now.Add(-time.Minute),
	}); err != nil {
		t.Fatalf("CreateDeviceAuth (expired): %v", err)
	}
	_, err = store.GetDeviceAuthByDeviceCode(ctx, "device-code-expired")
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for expired device_auth, got: %v", err)
	}
	n, err := store.DeleteExpiredDeviceAuths(ctx)
	if err != nil {
		t.Fatalf("DeleteExpiredDeviceAuths: %v", err)
	}
	if n < 1 {
		t.Errorf("DeleteExpiredDeviceAuths removed %d, want >= 1", n)
	}
}
