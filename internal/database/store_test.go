package database

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// testStoreContract runs the full CRUD test suite against any Store implementation.
// Each backend test file calls this with its own Store instance.
func testStoreContract(t *testing.T, store Store) {
	t.Run("AppCRUD", func(t *testing.T) { testAppCRUD(t, store) })
	t.Run("SetDefaultApp", func(t *testing.T) { testSetDefaultApp(t, store) })
	t.Run("UserCRUD", func(t *testing.T) { testUserCRUD(t, store) })
	t.Run("ProxyTokenCRUD", func(t *testing.T) { testProxyTokenCRUD(t, store) })
	t.Run("ProxyTokenWithAppID", func(t *testing.T) { testProxyTokenWithAppID(t, store) })
	t.Run("UpdateProxyTokenAppID", func(t *testing.T) { testUpdateProxyTokenAppID(t, store) })
	t.Run("GitHubTokenAppID", func(t *testing.T) { testGitHubTokenAppID(t, store) })
	t.Run("SyncAdminRoles", func(t *testing.T) { testSyncAdminRoles(t, store) })
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
		ExpiresAt:     time.Now().Add(24 * time.Hour),
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
		ExpiresAt:      time.Now().Add(365 * 24 * time.Hour),
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
		ExpiresAt:      time.Now().Add(24 * time.Hour),
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
		ExpiresAt:      time.Now().Add(24 * time.Hour),
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
		ExpiresAt:      time.Now().Add(24 * time.Hour),
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
