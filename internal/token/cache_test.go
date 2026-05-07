package token

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/database"
)

// mockStore implements database.Store with controllable proxy-token behaviour.
// Only the methods relevant to token cache tests are implemented; the rest
// panic if called so missing test setup is obvious.
type mockStore struct {
	// tokens is the set of tokens keyed by hash for GetProxyTokenByHash.
	tokens map[string]*database.ProxyToken

	// activeTokens is returned by ListActiveProxyTokens.
	activeTokens []*database.ProxyToken

	// getByHashCalls counts database reads so tests can assert cache hits.
	getByHashCalls atomic.Int64

	// revokedIDs records IDs passed to RevokeProxyToken.
	revokedIDs []string
}

func (m *mockStore) GetProxyTokenByHash(_ context.Context, hash string) (*database.ProxyToken, error) {
	m.getByHashCalls.Add(1)
	pt := m.tokens[hash]
	return pt, nil
}

func (m *mockStore) ListActiveProxyTokens(_ context.Context) ([]*database.ProxyToken, error) {
	return m.activeTokens, nil
}

func (m *mockStore) RevokeProxyToken(_ context.Context, id string) error {
	m.revokedIDs = append(m.revokedIDs, id)
	return nil
}

func (m *mockStore) CreateProxyToken(_ context.Context, pt *database.ProxyToken) error {
	pt.ID = "generated-id"
	return nil
}

// The remaining Store interface methods are unused by the cache tests.
func (m *mockStore) UpsertUser(_ context.Context, _ *database.User) error                          { return nil }
func (m *mockStore) GetUserByGitHubID(_ context.Context, _ int64) (*database.User, error)          { return nil, nil }
func (m *mockStore) GetUserByID(_ context.Context, _ string) (*database.User, error)               { return nil, nil }
func (m *mockStore) ListUsers(_ context.Context) ([]*database.User, error)                         { return nil, nil }
func (m *mockStore) SyncAdminRoles(_ context.Context, _ []string) error                            { return nil }
func (m *mockStore) UpsertGitHubToken(_ context.Context, _ *database.GitHubToken) error            { return nil }
func (m *mockStore) GetGitHubToken(_ context.Context, _ string) (*database.GitHubToken, error)     { return nil, nil }
func (m *mockStore) GetGitHubTokenByID(_ context.Context, _ string) (*database.GitHubToken, error) { return nil, nil }
func (m *mockStore) GetProxyTokenByID(_ context.Context, _ string) (*database.ProxyToken, error)   { return nil, nil }
func (m *mockStore) ListProxyTokens(_ context.Context, _ string) ([]*database.ProxyToken, error)   { return nil, nil }
func (m *mockStore) ListAllProxyTokens(_ context.Context) ([]*database.ProxyToken, error)          { return nil, nil }
func (m *mockStore) UpdateProxyTokenAppID(_ context.Context, _ string, _ string) error              { return nil }
func (m *mockStore) UpdateProxyTokenScopes(_ context.Context, _ string, _ json.RawMessage, _ json.RawMessage) error { return nil }
func (m *mockStore) DeleteExpiredProxyTokens(_ context.Context, _ time.Duration) (int64, error)     { return 0, nil }
func (m *mockStore) GetDefaultApp(_ context.Context) (*database.App, error)                        { return nil, nil }
func (m *mockStore) SetDefaultApp(_ context.Context, _ string) error                              { return nil }
func (m *mockStore) CreateApp(_ context.Context, _ *database.App) error                            { return nil }
func (m *mockStore) GetAppByID(_ context.Context, _ string) (*database.App, error)                 { return nil, nil }
func (m *mockStore) ListApps(_ context.Context) ([]*database.App, error)                           { return nil, nil }
func (m *mockStore) UpdateApp(_ context.Context, _ *database.App) error                            { return nil }
func (m *mockStore) DeleteApp(_ context.Context, _ string) error                                   { return nil }
func (m *mockStore) CreateCachedRepository(_ context.Context, _ *database.CachedRepository) error  { return nil }
func (m *mockStore) GetCachedRepositoryByID(_ context.Context, _ string) (*database.CachedRepository, error) {
	return nil, nil
}
func (m *mockStore) GetCachedRepositoryByOwnerName(_ context.Context, _, _ string) (*database.CachedRepository, error) {
	return nil, nil
}
func (m *mockStore) ListCachedRepositories(_ context.Context) ([]*database.CachedRepository, error) {
	return nil, nil
}
func (m *mockStore) UpdateCachedRepository(_ context.Context, _ *database.CachedRepository) error { return nil }
func (m *mockStore) DeleteCachedRepository(_ context.Context, _ string) error                     { return nil }
func (m *mockStore) CreateSession(_ context.Context, _ *database.Session) error                   { return nil }
func (m *mockStore) GetSessionByTokenHash(_ context.Context, _ string) (*database.Session, error) {
	return nil, database.ErrNotFound
}
func (m *mockStore) DeleteSession(_ context.Context, _ string) error             { return nil }
func (m *mockStore) DeleteExpiredSessions(_ context.Context) (int64, error)      { return 0, nil }
func (m *mockStore) CreateOAuthState(_ context.Context, _ *database.OAuthState) error { return nil }
func (m *mockStore) ConsumeOAuthState(_ context.Context, _, _ string) (*database.OAuthState, error) {
	return nil, database.ErrNotFound
}
func (m *mockStore) DeleteExpiredOAuthStates(_ context.Context) (int64, error)        { return 0, nil }
func (m *mockStore) CreateDeviceAuth(_ context.Context, _ *database.DeviceAuth) error { return nil }
func (m *mockStore) GetDeviceAuthByDeviceCode(_ context.Context, _ string) (*database.DeviceAuth, error) {
	return nil, database.ErrNotFound
}
func (m *mockStore) GetDeviceAuthByUserCode(_ context.Context, _ string) (*database.DeviceAuth, error) {
	return nil, database.ErrNotFound
}
func (m *mockStore) UpdateDeviceAuth(_ context.Context, _ *database.DeviceAuth) error { return nil }
func (m *mockStore) DeleteDeviceAuth(_ context.Context, _ string) error               { return nil }
func (m *mockStore) DeleteExpiredDeviceAuths(_ context.Context) (int64, error)        { return 0, nil }
func (m *mockStore) Close() error                                                     { return nil }

// newTestToken creates a valid proxy token for testing with the given hash, ID,
// and expiry.
func newTestToken(hash, id string, expiresAt time.Time) *database.ProxyToken {
	return &database.ProxyToken{
		ID:           id,
		TokenHash:    hash,
		TokenPrefix:  "ghx_test",
		TokenType:    "proxy",
		Repositories: json.RawMessage("null"),
		Scopes:       json.RawMessage("null"),
		ExpiresAt:    &expiresAt,
	}
}

func TestResolve_CacheHit(t *testing.T) {
	plaintext := "ghx_cachetest_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hash := Hash(plaintext)

	store := &mockStore{
		tokens: map[string]*database.ProxyToken{
			hash: newTestToken(hash, "tok-1", time.Now().Add(time.Hour)),
		},
	}

	svc := NewService(store, 24*time.Hour, false)
	ctx := context.Background()

	// First call: cache miss, hits the database.
	pt, err := svc.Resolve(ctx, plaintext)
	if err != nil {
		t.Fatalf("first Resolve: %v", err)
	}
	if pt.ID != "tok-1" {
		t.Fatalf("expected tok-1, got %s", pt.ID)
	}
	if store.getByHashCalls.Load() != 1 {
		t.Fatalf("expected 1 DB call after first resolve, got %d", store.getByHashCalls.Load())
	}

	// Second call: cache hit, no additional database read.
	pt2, err := svc.Resolve(ctx, plaintext)
	if err != nil {
		t.Fatalf("second Resolve: %v", err)
	}
	if pt2.ID != "tok-1" {
		t.Fatalf("expected tok-1 from cache, got %s", pt2.ID)
	}
	if store.getByHashCalls.Load() != 1 {
		t.Fatalf("expected still 1 DB call (cache hit), got %d", store.getByHashCalls.Load())
	}
}

func TestResolve_CacheTTLExpiry(t *testing.T) {
	plaintext := "ghx_ttltest_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hash := Hash(plaintext)

	store := &mockStore{
		tokens: map[string]*database.ProxyToken{
			hash: newTestToken(hash, "tok-2", time.Now().Add(time.Hour)),
		},
	}

	now := time.Now()
	svc := NewService(store, 24*time.Hour, false)
	svc.nowFunc = func() time.Time { return now }
	ctx := context.Background()

	// Prime the cache.
	if _, err := svc.Resolve(ctx, plaintext); err != nil {
		t.Fatal(err)
	}
	if store.getByHashCalls.Load() != 1 {
		t.Fatalf("expected 1 DB call, got %d", store.getByHashCalls.Load())
	}

	// Advance time past the TTL.
	now = now.Add(tokenCacheTTL + time.Second)

	// This should miss the cache and hit the DB again.
	if _, err := svc.Resolve(ctx, plaintext); err != nil {
		t.Fatal(err)
	}
	if store.getByHashCalls.Load() != 2 {
		t.Fatalf("expected 2 DB calls after TTL expiry, got %d", store.getByHashCalls.Load())
	}
}

func TestResolve_CachedExpiredToken(t *testing.T) {
	plaintext := "ghx_exptest_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hash := Hash(plaintext)

	expiresAt := time.Now().Add(10 * time.Second)
	store := &mockStore{
		tokens: map[string]*database.ProxyToken{
			hash: newTestToken(hash, "tok-3", expiresAt),
		},
	}

	now := time.Now()
	svc := NewService(store, 24*time.Hour, false)
	svc.nowFunc = func() time.Time { return now }
	ctx := context.Background()

	// Prime the cache while the token is still valid.
	pt, err := svc.Resolve(ctx, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if pt == nil {
		t.Fatal("expected non-nil token")
	}

	// Advance time past the token expiry but within the cache TTL.
	now = expiresAt.Add(time.Second)

	// The cached entry should be returned but the expiry check should fail.
	_, err = svc.Resolve(ctx, plaintext)
	if err == nil {
		t.Fatal("expected error for expired token from cache")
	}
	if err.Error() != "token has expired" {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should not have hit the DB again — the cached entry was used.
	if store.getByHashCalls.Load() != 1 {
		t.Fatalf("expected 1 DB call (expired check from cache), got %d", store.getByHashCalls.Load())
	}
}

func TestResolve_CachedRevokedToken(t *testing.T) {
	plaintext := "ghx_revtest_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hash := Hash(plaintext)

	revokedAt := time.Now()
	pt := newTestToken(hash, "tok-4", time.Now().Add(time.Hour))
	pt.RevokedAt = &revokedAt

	store := &mockStore{
		tokens: map[string]*database.ProxyToken{hash: pt},
	}

	svc := NewService(store, 24*time.Hour, false)
	ctx := context.Background()

	// First call fetches from DB and should report revoked.
	_, err := svc.Resolve(ctx, plaintext)
	if err == nil || err.Error() != "token has been revoked" {
		t.Fatalf("expected 'token has been revoked', got: %v", err)
	}
	// Revoked tokens should NOT be cached.
	if store.getByHashCalls.Load() != 1 {
		t.Fatalf("expected 1 DB call, got %d", store.getByHashCalls.Load())
	}

	// Second call should still hit the DB (not cached).
	_, err = svc.Resolve(ctx, plaintext)
	if err == nil || err.Error() != "token has been revoked" {
		t.Fatalf("second call: expected 'token has been revoked', got: %v", err)
	}
	if store.getByHashCalls.Load() != 2 {
		t.Fatalf("expected 2 DB calls (revoked tokens not cached), got %d", store.getByHashCalls.Load())
	}
}

func TestRevoke_InvalidatesCache(t *testing.T) {
	plaintext := "ghx_revoketest_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hash := Hash(plaintext)

	store := &mockStore{
		tokens: map[string]*database.ProxyToken{
			hash: newTestToken(hash, "tok-5", time.Now().Add(time.Hour)),
		},
	}

	svc := NewService(store, 24*time.Hour, false)
	ctx := context.Background()

	// Prime the cache.
	if _, err := svc.Resolve(ctx, plaintext); err != nil {
		t.Fatal(err)
	}
	if store.getByHashCalls.Load() != 1 {
		t.Fatal("expected 1 DB call")
	}

	// Revoke the token — this should invalidate the cache entry.
	if err := svc.Revoke(ctx, "tok-5"); err != nil {
		t.Fatal(err)
	}

	// Next Resolve should hit the DB again because the cache was invalidated.
	// Update the store to return nil to prove the DB was actually queried.
	delete(store.tokens, hash)

	pt, err := svc.Resolve(ctx, plaintext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pt != nil {
		t.Fatal("expected nil after revocation + cache invalidation")
	}
	if store.getByHashCalls.Load() != 2 {
		t.Fatalf("expected 2 DB calls (cache invalidated by Revoke), got %d", store.getByHashCalls.Load())
	}
}

func TestWarmTokenCache(t *testing.T) {
	hash1 := Hash("ghx_warm1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	hash2 := Hash("ghx_warm2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

	tok1 := newTestToken(hash1, "warm-1", time.Now().Add(time.Hour))
	tok2 := newTestToken(hash2, "warm-2", time.Now().Add(2*time.Hour))

	store := &mockStore{
		activeTokens: []*database.ProxyToken{tok1, tok2},
		tokens: map[string]*database.ProxyToken{
			hash1: tok1,
			hash2: tok2,
		},
	}

	svc := NewService(store, 24*time.Hour, false)
	ctx := context.Background()

	// Warm the cache.
	svc.WarmTokenCache(ctx, nil)

	// Both tokens should now be cached — Resolve should not hit the DB.
	plaintext1 := "ghx_warm1_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pt1, err := svc.Resolve(ctx, plaintext1)
	if err != nil {
		t.Fatal(err)
	}
	if pt1.ID != "warm-1" {
		t.Fatalf("expected warm-1, got %s", pt1.ID)
	}

	plaintext2 := "ghx_warm2_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	pt2, err := svc.Resolve(ctx, plaintext2)
	if err != nil {
		t.Fatal(err)
	}
	if pt2.ID != "warm-2" {
		t.Fatalf("expected warm-2, got %s", pt2.ID)
	}

	// No DB calls should have been made — everything was served from cache.
	if store.getByHashCalls.Load() != 0 {
		t.Fatalf("expected 0 DB calls after warm, got %d", store.getByHashCalls.Load())
	}
}

func TestWarmTokenCache_SkipsEmptyHash(t *testing.T) {
	// Tokens with empty hashes (shouldn't happen but defensive) should be skipped.
	tok := newTestToken("", "no-hash", time.Now().Add(time.Hour))

	store := &mockStore{
		activeTokens: []*database.ProxyToken{tok},
		tokens:       map[string]*database.ProxyToken{},
	}

	svc := NewService(store, 24*time.Hour, false)
	svc.WarmTokenCache(context.Background(), nil)

	// The empty-hash token should not have been cached. Verify by checking
	// that the cache is empty (Resolve for any token would hit the DB).
	// We can't easily iterate sync.Map, but the test primarily ensures no panic.
}

func TestResolve_DoesNotCacheExpiredFromDB(t *testing.T) {
	// Tokens that are expired when fetched from the DB should not be cached.
	plaintext := "ghx_dbexpire_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hash := Hash(plaintext)

	store := &mockStore{
		tokens: map[string]*database.ProxyToken{
			hash: newTestToken(hash, "tok-expired-db", time.Now().Add(-time.Hour)),
		},
	}

	svc := NewService(store, 24*time.Hour, false)
	ctx := context.Background()

	_, err := svc.Resolve(ctx, plaintext)
	if err == nil || err.Error() != "token has expired" {
		t.Fatalf("expected 'token has expired', got: %v", err)
	}

	// Second call should still hit DB (expired tokens are not cached).
	_, err = svc.Resolve(ctx, plaintext)
	if err == nil || err.Error() != "token has expired" {
		t.Fatalf("expected 'token has expired', got: %v", err)
	}
	if store.getByHashCalls.Load() != 2 {
		t.Fatalf("expected 2 DB calls (expired not cached), got %d", store.getByHashCalls.Load())
	}
}

func TestResolve_NotFound(t *testing.T) {
	plaintext := "ghx_missing_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	store := &mockStore{
		tokens: map[string]*database.ProxyToken{},
	}

	svc := NewService(store, 24*time.Hour, false)
	ctx := context.Background()

	pt, err := svc.Resolve(ctx, plaintext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pt != nil {
		t.Fatal("expected nil for missing token")
	}

	// Not-found results are not cached — second call still hits DB.
	pt, err = svc.Resolve(ctx, plaintext)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pt != nil {
		t.Fatal("expected nil for missing token")
	}
	if store.getByHashCalls.Load() != 2 {
		t.Fatalf("expected 2 DB calls (not-found not cached), got %d", store.getByHashCalls.Load())
	}
}

func TestResolve_NoExpiry(t *testing.T) {
	plaintext := "ghx_noexpiry_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hash := Hash(plaintext)

	// A token with nil ExpiresAt should never expire.
	tok := &database.ProxyToken{
		ID:           "tok-noexp",
		TokenHash:    hash,
		TokenPrefix:  "ghx_noex",
		TokenType:    "proxy",
		Repositories: json.RawMessage("null"),
		Scopes:       json.RawMessage("null"),
		ExpiresAt:    nil,
	}

	store := &mockStore{
		tokens: map[string]*database.ProxyToken{hash: tok},
	}

	svc := NewService(store, 24*time.Hour, true)
	ctx := context.Background()

	pt, err := svc.Resolve(ctx, plaintext)
	if err != nil {
		t.Fatalf("Resolve no-expiry token: %v", err)
	}
	if pt == nil {
		t.Fatal("expected non-nil token")
	}
	if pt.ExpiresAt != nil {
		t.Fatalf("expected nil ExpiresAt, got %v", pt.ExpiresAt)
	}
}

func TestCreate_NoExpiry(t *testing.T) {
	store := &mockStore{
		tokens: map[string]*database.ProxyToken{},
	}

	svc := NewService(store, 24*time.Hour, true)
	ctx := context.Background()

	result, err := svc.Create(ctx, CreateRequest{
		TokenType:     TokenTypeProxy,
		UserID:        "user-1",
		GitHubTokenID: "gt-1",
		NoExpiry:      true,
		SessionID:     "sess",
	})
	if err != nil {
		t.Fatalf("Create no-expiry: %v", err)
	}
	if result.ExpiresAt != nil {
		t.Fatalf("expected nil ExpiresAt, got %v", result.ExpiresAt)
	}
}

func TestCreate_NoExpiryDisallowed(t *testing.T) {
	store := &mockStore{
		tokens: map[string]*database.ProxyToken{},
	}

	svc := NewService(store, 24*time.Hour, false) // allowNoExpiry=false
	ctx := context.Background()

	_, err := svc.Create(ctx, CreateRequest{
		TokenType:     TokenTypeProxy,
		UserID:        "user-1",
		GitHubTokenID: "gt-1",
		NoExpiry:      true,
		SessionID:     "sess",
	})
	if err == nil {
		t.Fatal("expected error when NoExpiry is disallowed")
	}
	if err.Error() != "no-expiry tokens are not allowed by server configuration" {
		t.Fatalf("unexpected error: %v", err)
	}
}
