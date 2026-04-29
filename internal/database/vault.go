package database

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	vault "github.com/hashicorp/vault/api"
)

// VaultStore implements Store using HashiCorp Vault KV v2 secrets engine.
type VaultStore struct {
	client    *vault.Client
	mountPath string // KV v2 mount path, e.g. "secret"
	basePath  string // prefix within the mount, e.g. "ghp"

	// Stored for re-authentication when the token expires.
	roleID   string
	secretID string
}

// VaultConfig holds configuration for Vault connectivity.
type VaultConfig struct {
	Addr      string // Vault server address
	RoleID    string // AppRole role ID
	SecretID  string // AppRole secret ID
	MountPath string // KV v2 mount path (default: "secret")
	BasePath  string // key prefix (default: "ghp")
}

// NewVaultStore creates a VaultStore authenticated via AppRole.
func NewVaultStore(ctx context.Context, cfg VaultConfig) (*VaultStore, error) {
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = cfg.Addr

	client, err := vault.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}

	mountPath := cfg.MountPath
	if mountPath == "" {
		mountPath = "secret"
	}
	basePath := cfg.BasePath
	if basePath == "" {
		basePath = "ghp"
	}

	store := &VaultStore{
		client:    client,
		mountPath: mountPath,
		basePath:  basePath,
		roleID:    cfg.RoleID,
		secretID:  cfg.SecretID,
	}

	// Authenticate via AppRole.
	if err := store.login(ctx); err != nil {
		return nil, fmt.Errorf("vault approle login: %w", err)
	}

	return store, nil
}

// login authenticates to Vault using the stored AppRole credentials.
// It is safe to call repeatedly; each call replaces the current token.
func (s *VaultStore) login(ctx context.Context) error {
	loginResp, err := s.client.Logical().WriteWithContext(ctx, "auth/approle/login", map[string]interface{}{
		"role_id":   s.roleID,
		"secret_id": s.secretID,
	})
	if err != nil {
		return fmt.Errorf("approle login: %w", err)
	}
	if loginResp == nil || loginResp.Auth == nil {
		return fmt.Errorf("approle login returned no auth token")
	}
	s.client.SetToken(loginResp.Auth.ClientToken)
	return nil
}

// withRelogin executes fn; if fn returns a 403 (expired/invalid token) it
// re-authenticates once and retries. This transparently handles AppRole
// tokens that expire during the server's lifetime.
func (s *VaultStore) withRelogin(ctx context.Context, fn func() error) error {
	err := fn()
	if err == nil {
		return nil
	}
	// Check for a structured Vault 403 response, which indicates an expired or
	// invalid token. Fall back to string matching for non-ResponseError paths
	// (e.g. wrapped errors from helper functions).
	var respErr *vault.ResponseError
	is403 := errors.As(err, &respErr) && respErr.StatusCode == 403
	if !is403 {
		is403 = strings.Contains(err.Error(), "permission denied")
	}
	if is403 {
		if reloginErr := s.login(ctx); reloginErr != nil {
			// Return original error — re-login failed.
			return err
		}
		return fn()
	}
	return err
}

// NewVaultStoreFromClient creates a VaultStore from an existing authenticated client.
// Primarily used for testing.
func NewVaultStoreFromClient(client *vault.Client, mountPath, basePath string) *VaultStore {
	if mountPath == "" {
		mountPath = "secret"
	}
	if basePath == "" {
		basePath = "ghp"
	}
	return &VaultStore{
		client:    client,
		mountPath: mountPath,
		basePath:  basePath,
	}
}

func (s *VaultStore) Close() error {
	return nil
}

// dataPath returns the KV v2 data path for the given key.
func (s *VaultStore) dataPath(key string) string {
	return fmt.Sprintf("%s/data/%s/%s", s.mountPath, s.basePath, key)
}

// metadataPath returns the KV v2 metadata path for the given key.
func (s *VaultStore) metadataPath(key string) string {
	return fmt.Sprintf("%s/metadata/%s/%s", s.mountPath, s.basePath, key)
}

// kvWrite writes data to a KV v2 path. Re-authenticates once on 403 errors.
func (s *VaultStore) kvWrite(ctx context.Context, key string, data map[string]interface{}) error {
	return s.withRelogin(ctx, func() error {
		_, err := s.client.Logical().WriteWithContext(ctx, s.dataPath(key), map[string]interface{}{
			"data": data,
		})
		return err
	})
}

// errKVAlreadyExists is returned by kvCreate when the target path already
// has a non-deleted value. Vault surfaces a CAS mismatch as an HTTP 400 with
// a specific "check-and-set parameter did not match the current version"
// error, which is what we look for here.
var errKVAlreadyExists = errors.New("kv: already exists")

// kvCreate writes data to a KV v2 path only if no value exists there. It
// uses KV v2's check-and-set option (`cas: 0`) so the operation is atomic
// and concurrent callers cannot race past each other to overwrite the same
// key. Returns errKVAlreadyExists if the key is already present.
//
// Re-authenticates once on 403 errors via withRelogin, like the other KV
// helpers; CAS conflicts are returned to the caller as errKVAlreadyExists
// so they can be distinguished from authentication failures.
func (s *VaultStore) kvCreate(ctx context.Context, key string, data map[string]interface{}) error {
	return s.withRelogin(ctx, func() error {
		_, err := s.client.Logical().WriteWithContext(ctx, s.dataPath(key), map[string]interface{}{
			"data":    data,
			"options": map[string]interface{}{"cas": 0},
		})
		if err != nil && isKVCASMismatch(err) {
			return errKVAlreadyExists
		}
		return err
	})
}

// isKVCASMismatch detects the specific Vault response that indicates a
// check-and-set conflict so the caller can surface a typed error. Vault
// emits the phrase "check-and-set parameter did not match" in the body of
// a 400 response on a CAS conflict; structured detection via
// vault.ResponseError would be preferable but the response error type
// embedded in the SDK does not expose a code we can match on directly.
func isKVCASMismatch(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "check-and-set") ||
		strings.Contains(err.Error(), "cas parameter")
}

// kvRead reads data from a KV v2 path. Returns nil, nil if not found.
// Re-authenticates once on 403 errors.
func (s *VaultStore) kvRead(ctx context.Context, key string) (map[string]interface{}, error) {
	var secret *vault.Secret
	err := s.withRelogin(ctx, func() error {
		var readErr error
		secret, readErr = s.client.Logical().ReadWithContext(ctx, s.dataPath(key))
		return readErr
	})
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, nil
	}
	result, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, nil
	}
	return result, nil
}

// kvDelete deletes a secret at the given path (destroys all versions via metadata).
// Re-authenticates once on 403 errors.
func (s *VaultStore) kvDelete(ctx context.Context, key string) error {
	return s.withRelogin(ctx, func() error {
		_, err := s.client.Logical().DeleteWithContext(ctx, s.metadataPath(key))
		return err
	})
}

// kvList lists keys at the given path prefix. Returns nil if empty.
// Re-authenticates once on 403 errors.
func (s *VaultStore) kvList(ctx context.Context, key string) ([]string, error) {
	var secret *vault.Secret
	err := s.withRelogin(ctx, func() error {
		var listErr error
		secret, listErr = s.client.Logical().ListWithContext(ctx, s.metadataPath(key))
		return listErr
	})
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, nil
	}
	keys, ok := secret.Data["keys"].([]interface{})
	if !ok {
		return nil, nil
	}
	result := make([]string, 0, len(keys))
	for _, k := range keys {
		if s, ok := k.(string); ok {
			result = append(result, strings.TrimSuffix(s, "/"))
		}
	}
	return result, nil
}

// --- Helper functions for marshaling/unmarshaling ---

func marshalToMap(v interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	// Use json.Decoder with UseNumber so that numeric fields (e.g. int64 App.AppID)
	// are preserved as json.Number rather than float64.
	// float64 loses precision for integers > 2^53, and re-marshalling json.Number
	// values produces the original decimal representation, so the round-trip is exact.
	var m map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}

func unmarshalFromMap(data map[string]interface{}, v interface{}) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// --- Apps ---

func (s *VaultStore) CreateApp(ctx context.Context, app *App) error {
	if app.ID == "" {
		app.ID = uuid.New().String()
	}
	now := time.Now().UTC()
	app.CreatedAt = now
	app.UpdatedAt = now

	data, err := marshalToMap(app)
	if err != nil {
		return fmt.Errorf("marshaling app: %w", err)
	}
	return s.kvWrite(ctx, "apps/"+app.ID, data)
}

func (s *VaultStore) GetAppByID(ctx context.Context, id string) (*App, error) {
	data, err := s.kvRead(ctx, "apps/"+id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	var app App
	if err := unmarshalFromMap(data, &app); err != nil {
		return nil, err
	}
	return &app, nil
}

func (s *VaultStore) GetDefaultApp(ctx context.Context) (*App, error) {
	apps, err := s.ListApps(ctx)
	if err != nil {
		return nil, err
	}
	for _, a := range apps {
		if a.IsDefault {
			return a, nil
		}
	}
	return nil, nil
}

func (s *VaultStore) ListApps(ctx context.Context) ([]*App, error) {
	keys, err := s.kvList(ctx, "apps")
	if err != nil {
		return nil, err
	}
	var apps []*App
	for _, key := range keys {
		app, err := s.GetAppByID(ctx, key)
		if err != nil {
			return nil, err
		}
		if app != nil {
			apps = append(apps, app)
		}
	}
	return apps, nil
}

func (s *VaultStore) UpdateApp(ctx context.Context, app *App) error {
	existing, err := s.GetAppByID(ctx, app.ID)
	if err != nil {
		return err
	}
	if existing == nil {
		return fmt.Errorf("app %s: %w", app.ID, ErrNotFound)
	}
	app.CreatedAt = existing.CreatedAt // preserve immutable field
	app.UpdatedAt = time.Now().UTC()
	data, err := marshalToMap(app)
	if err != nil {
		return fmt.Errorf("marshaling app: %w", err)
	}
	return s.kvWrite(ctx, "apps/"+app.ID, data)
}

func (s *VaultStore) SetDefaultApp(ctx context.Context, appID string) error {
	// Vault has no transaction support. Follow the set-then-clear pattern
	// documented in CLAUDE.md: set the new default first so that a partial
	// failure never leaves the system with no default app.
	target, err := s.GetAppByID(ctx, appID)
	if err != nil {
		return err
	}
	if target == nil {
		return fmt.Errorf("app %s: %w", appID, ErrNotFound)
	}

	// Set the target as default.
	target.IsDefault = true
	target.UpdatedAt = time.Now().UTC()
	data, err := marshalToMap(target)
	if err != nil {
		return fmt.Errorf("marshaling app: %w", err)
	}
	if err := s.kvWrite(ctx, "apps/"+target.ID, data); err != nil {
		return err
	}

	// Now clear the default flag on all other apps.
	apps, err := s.ListApps(ctx)
	if err != nil {
		return err
	}
	for _, app := range apps {
		if app.ID == appID || !app.IsDefault {
			continue
		}
		app.IsDefault = false
		app.UpdatedAt = time.Now().UTC()
		clearData, err := marshalToMap(app)
		if err != nil {
			return fmt.Errorf("marshaling app: %w", err)
		}
		if err := s.kvWrite(ctx, "apps/"+app.ID, clearData); err != nil {
			return err
		}
	}

	return nil
}

func (s *VaultStore) DeleteApp(ctx context.Context, id string) error {
	existing, err := s.GetAppByID(ctx, id)
	if err != nil {
		return err
	}
	if existing == nil {
		return fmt.Errorf("app %s: %w", id, ErrNotFound)
	}
	return s.kvDelete(ctx, "apps/"+id)
}

// --- Users ---

func (s *VaultStore) UpsertUser(ctx context.Context, user *User) error {
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	now := time.Now().UTC()

	// Check if user exists by GitHub ID via index.
	existing, err := s.GetUserByGitHubID(ctx, user.GitHubID)
	if err != nil {
		return err
	}
	if existing != nil {
		user.ID = existing.ID
		user.CreatedAt = existing.CreatedAt
		user.UpdatedAt = now
	} else {
		user.CreatedAt = now
		user.UpdatedAt = now
	}

	data, err := marshalToMap(user)
	if err != nil {
		return fmt.Errorf("marshaling user: %w", err)
	}
	if err := s.kvWrite(ctx, "users/"+user.ID, data); err != nil {
		return err
	}
	// Write GitHub ID index.
	return s.kvWrite(ctx, fmt.Sprintf("users/by-github-id/%d", user.GitHubID), map[string]interface{}{
		"id": user.ID,
	})
}

func (s *VaultStore) GetUserByGitHubID(ctx context.Context, githubID int64) (*User, error) {
	indexData, err := s.kvRead(ctx, fmt.Sprintf("users/by-github-id/%d", githubID))
	if err != nil {
		return nil, err
	}
	if indexData == nil {
		return nil, nil
	}
	id, ok := indexData["id"].(string)
	if !ok {
		return nil, nil
	}
	return s.GetUserByID(ctx, id)
}

func (s *VaultStore) GetUserByID(ctx context.Context, id string) (*User, error) {
	data, err := s.kvRead(ctx, "users/"+id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	var user User
	if err := unmarshalFromMap(data, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (s *VaultStore) ListUsers(ctx context.Context) ([]*User, error) {
	keys, err := s.kvList(ctx, "users")
	if err != nil {
		return nil, err
	}
	var users []*User
	for _, key := range keys {
		// Skip index paths.
		if key == "by-github-id" {
			continue
		}
		user, err := s.GetUserByID(ctx, key)
		if err != nil {
			return nil, err
		}
		if user != nil {
			users = append(users, user)
		}
	}
	return users, nil
}

func (s *VaultStore) SyncAdminRoles(ctx context.Context, adminUsernames []string) error {
	users, err := s.ListUsers(ctx)
	if err != nil {
		return err
	}

	adminSet := make(map[string]bool)
	for _, u := range adminUsernames {
		adminSet[strings.ToLower(u)] = true
	}

	for _, user := range users {
		newRole := "user"
		if adminSet[strings.ToLower(user.GitHubUsername)] {
			newRole = "admin"
		}
		if user.Role != newRole {
			user.Role = newRole
			user.UpdatedAt = time.Now().UTC()
			data, err := marshalToMap(user)
			if err != nil {
				return err
			}
			if err := s.kvWrite(ctx, "users/"+user.ID, data); err != nil {
				return err
			}
		}
	}
	return nil
}

// --- GitHub Tokens ---

func (s *VaultStore) UpsertGitHubToken(ctx context.Context, token *GitHubToken) error {
	if token.ID == "" {
		token.ID = uuid.New().String()
	}
	now := time.Now().UTC()

	// Check existing by user ID index.
	existing, err := s.GetGitHubToken(ctx, token.UserID)
	if err != nil {
		return err
	}
	if existing != nil {
		token.ID = existing.ID
		token.CreatedAt = existing.CreatedAt
		token.UpdatedAt = now
	} else {
		token.CreatedAt = now
		token.UpdatedAt = now
	}

	data, err := marshalToMap(token)
	if err != nil {
		return fmt.Errorf("marshaling github token: %w", err)
	}
	if err := s.kvWrite(ctx, "github-tokens/"+token.ID, data); err != nil {
		return err
	}
	// Write user ID index.
	return s.kvWrite(ctx, "github-tokens/by-user/"+token.UserID, map[string]interface{}{
		"id": token.ID,
	})
}

func (s *VaultStore) GetGitHubToken(ctx context.Context, userID string) (*GitHubToken, error) {
	indexData, err := s.kvRead(ctx, "github-tokens/by-user/"+userID)
	if err != nil {
		return nil, err
	}
	if indexData == nil {
		return nil, nil
	}
	id, ok := indexData["id"].(string)
	if !ok {
		return nil, nil
	}
	return s.GetGitHubTokenByID(ctx, id)
}

func (s *VaultStore) GetGitHubTokenByID(ctx context.Context, id string) (*GitHubToken, error) {
	data, err := s.kvRead(ctx, "github-tokens/"+id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	var token GitHubToken
	if err := unmarshalFromMap(data, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

// --- Proxy Tokens ---

func (s *VaultStore) CreateProxyToken(ctx context.Context, token *ProxyToken) error {
	if token.ID == "" {
		token.ID = uuid.New().String()
	}
	now := time.Now().UTC()
	token.CreatedAt = now
	if token.TokenType == "" {
		token.TokenType = DefaultTokenType
	}

	if err := s.writeProxyToken(ctx, token); err != nil {
		return err
	}
	// Write hash index.
	if err := s.kvWrite(ctx, "proxy-tokens/by-hash/"+token.TokenHash, map[string]interface{}{
		"id": token.ID,
	}); err != nil {
		return err
	}
	// Write user index if user ID is set.
	if token.UserID != nil && *token.UserID != "" {
		if err := s.kvWrite(ctx, "proxy-tokens/by-user/"+*token.UserID+"/"+token.ID, map[string]interface{}{
			"id": token.ID,
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *VaultStore) GetProxyTokenByHash(ctx context.Context, hash string) (*ProxyToken, error) {
	indexData, err := s.kvRead(ctx, "proxy-tokens/by-hash/"+hash)
	if err != nil {
		return nil, err
	}
	if indexData == nil {
		return nil, nil
	}
	id, ok := indexData["id"].(string)
	if !ok {
		return nil, nil
	}
	return s.GetProxyTokenByID(ctx, id)
}

func (s *VaultStore) GetProxyTokenByID(ctx context.Context, id string) (*ProxyToken, error) {
	data, err := s.kvRead(ctx, "proxy-tokens/"+id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	var token ProxyToken
	if err := unmarshalFromMap(data, &token); err != nil {
		return nil, err
	}
	// Restore token_hash from vault data since json:"-" skips it.
	if hash, ok := data["token_hash"].(string); ok {
		token.TokenHash = hash
	}
	return &token, nil
}

func (s *VaultStore) ListProxyTokens(ctx context.Context, userID string) ([]*ProxyToken, error) {
	keys, err := s.kvList(ctx, "proxy-tokens/by-user/"+userID)
	if err != nil {
		return nil, err
	}
	var tokens []*ProxyToken
	for _, key := range keys {
		token, err := s.GetProxyTokenByID(ctx, key)
		if err != nil {
			return nil, err
		}
		if token != nil {
			tokens = append(tokens, token)
		}
	}
	return tokens, nil
}

func (s *VaultStore) ListAllProxyTokens(ctx context.Context) ([]*ProxyToken, error) {
	keys, err := s.kvList(ctx, "proxy-tokens")
	if err != nil {
		return nil, err
	}
	var tokens []*ProxyToken
	for _, key := range keys {
		// Skip index paths.
		if key == "by-hash" || key == "by-user" {
			continue
		}
		token, err := s.GetProxyTokenByID(ctx, key)
		if err != nil {
			return nil, err
		}
		if token != nil {
			tokens = append(tokens, token)
		}
	}
	return tokens, nil
}

func (s *VaultStore) ListActiveProxyTokens(ctx context.Context) ([]*ProxyToken, error) {
	all, err := s.ListAllProxyTokens(ctx)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var active []*ProxyToken
	for _, t := range all {
		if t.RevokedAt == nil && (t.ExpiresAt == nil || t.ExpiresAt.After(now)) {
			active = append(active, t)
		}
	}
	return active, nil
}

// writeProxyToken marshals a ProxyToken and writes it to Vault, preserving
// the token_hash field that is excluded from JSON serialization.
func (s *VaultStore) writeProxyToken(ctx context.Context, t *ProxyToken) error {
	data, err := marshalToMap(t)
	if err != nil {
		return err
	}
	data["token_hash"] = t.TokenHash
	return s.kvWrite(ctx, "proxy-tokens/"+t.ID, data)
}

func (s *VaultStore) RevokeProxyToken(ctx context.Context, id string) error {
	token, err := s.GetProxyTokenByID(ctx, id)
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("token not found or already revoked")
	}
	if token.RevokedAt != nil {
		return fmt.Errorf("token not found or already revoked")
	}
	now := time.Now().UTC()
	token.RevokedAt = &now
	return s.writeProxyToken(ctx, token)
}

func (s *VaultStore) UpdateProxyTokenAppID(ctx context.Context, id string, appID string) error {
	token, err := s.GetProxyTokenByID(ctx, id)
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("proxy token %s: %w", id, ErrNotFound)
	}
	token.AppID = &appID
	return s.writeProxyToken(ctx, token)
}

func (s *VaultStore) UpdateProxyTokenScopes(ctx context.Context, id string, repositories json.RawMessage, scopes json.RawMessage) error {
	token, err := s.GetProxyTokenByID(ctx, id)
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("proxy token %s: %w", id, ErrNotFound)
	}
	token.Repositories = repositories
	token.Scopes = scopes
	return s.writeProxyToken(ctx, token)
}

func (s *VaultStore) DeleteExpiredProxyTokens(ctx context.Context, olderThan time.Duration) (int64, error) {
	if olderThan <= 0 {
		return 0, fmt.Errorf("DeleteExpiredProxyTokens: olderThan must be positive, got %v", olderThan)
	}
	cutoff := time.Now().UTC().Add(-olderThan)

	all, err := s.ListAllProxyTokens(ctx)
	if err != nil {
		return 0, err
	}

	var deleted int64
	var firstErr error
	for _, t := range all {
		// Stop early on context cancellation so shutdown is not delayed by
		// a loop full of kvDelete calls that would all fail fast anyway.
		if ctx.Err() != nil {
			if firstErr == nil {
				firstErr = ctx.Err()
			}
			break
		}

		// Evaluate the two conditions independently so the Vault backend
		// matches the SQL backends: a token is eligible if EITHER revoked_at
		// OR expires_at is older than the cutoff. Using `else if` would keep
		// a long-expired token that was recently revoked, diverging from the
		// SQL `WHERE (revoked_at < $1) OR (expires_at < $1)` semantics.
		shouldDelete := false
		if t.RevokedAt != nil && t.RevokedAt.Before(cutoff) {
			shouldDelete = true
		}
		if t.ExpiresAt != nil && t.ExpiresAt.Before(cutoff) {
			shouldDelete = true
		}
		if !shouldDelete {
			continue
		}

		// Remove index entries before the main record so a failure cannot
		// leave orphaned indexes pointing at a deleted record. kvDelete is
		// idempotent on Vault, so retrying on the next cycle is safe.
		if t.TokenHash != "" {
			if err := s.kvDelete(ctx, "proxy-tokens/by-hash/"+t.TokenHash); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("deleting hash index for proxy token %s: %w", t.ID, err)
				}
				continue
			}
		}

		if t.UserID != nil && *t.UserID != "" {
			if err := s.kvDelete(ctx, "proxy-tokens/by-user/"+*t.UserID+"/"+t.ID); err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("deleting user index for proxy token %s: %w", t.ID, err)
				}
				continue
			}
		}

		// Delete the main record last. On failure, continue so a single
		// transient Vault error does not abort the whole cleanup cycle.
		if err := s.kvDelete(ctx, "proxy-tokens/"+t.ID); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("deleting proxy token %s: %w", t.ID, err)
			}
			continue
		}
		deleted++
	}
	return deleted, firstErr
}

// --- Cached Repositories ---

func (s *VaultStore) CreateCachedRepository(ctx context.Context, repo *CachedRepository) error {
	if repo.ID == "" {
		repo.ID = uuid.New().String()
	}
	now := time.Now().UTC()
	repo.CreatedAt = now
	repo.UpdatedAt = now

	// Check uniqueness before writing the record to avoid orphaned entries.
	indexPath := fmt.Sprintf("cached-repos/by-owner-name/%s/%s", repo.Owner, repo.Name)
	existing, err := s.kvRead(ctx, indexPath)
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("cached repository %s/%s already exists", repo.Owner, repo.Name)
	}

	data, err := marshalToMap(repo)
	if err != nil {
		return fmt.Errorf("marshaling cached repository: %w", err)
	}
	if err := s.kvWrite(ctx, "cached-repos/"+repo.ID, data); err != nil {
		return err
	}
	return s.kvWrite(ctx, indexPath, map[string]interface{}{
		"id": repo.ID,
	})
}

func (s *VaultStore) GetCachedRepositoryByID(ctx context.Context, id string) (*CachedRepository, error) {
	data, err := s.kvRead(ctx, "cached-repos/"+id)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	var repo CachedRepository
	if err := unmarshalFromMap(data, &repo); err != nil {
		return nil, err
	}
	return &repo, nil
}

func (s *VaultStore) GetCachedRepositoryByOwnerName(ctx context.Context, owner, name string) (*CachedRepository, error) {
	indexData, err := s.kvRead(ctx, fmt.Sprintf("cached-repos/by-owner-name/%s/%s", owner, name))
	if err != nil {
		return nil, err
	}
	if indexData == nil {
		return nil, nil
	}
	id, ok := indexData["id"].(string)
	if !ok {
		return nil, nil
	}
	return s.GetCachedRepositoryByID(ctx, id)
}

func (s *VaultStore) ListCachedRepositories(ctx context.Context) ([]*CachedRepository, error) {
	keys, err := s.kvList(ctx, "cached-repos")
	if err != nil {
		return nil, err
	}
	var repos []*CachedRepository
	for _, key := range keys {
		// Skip index paths.
		if key == "by-owner-name" {
			continue
		}
		repo, err := s.GetCachedRepositoryByID(ctx, key)
		if err != nil {
			return nil, err
		}
		if repo != nil {
			repos = append(repos, repo)
		}
	}
	return repos, nil
}

func (s *VaultStore) UpdateCachedRepository(ctx context.Context, repo *CachedRepository) error {
	existing, err := s.GetCachedRepositoryByID(ctx, repo.ID)
	if err != nil {
		return err
	}
	if existing == nil {
		return fmt.Errorf("cached repository %s: %w", repo.ID, ErrNotFound)
	}

	// If owner/name changed, check for conflicts before writing anything.
	ownerNameChanged := existing.Owner != repo.Owner || existing.Name != repo.Name

	if ownerNameChanged {
		newIndexPath := fmt.Sprintf("cached-repos/by-owner-name/%s/%s", repo.Owner, repo.Name)
		conflicting, err := s.kvRead(ctx, newIndexPath)
		if err != nil {
			return err
		}
		if conflicting != nil {
			return fmt.Errorf("cached repository %s/%s already exists", repo.Owner, repo.Name)
		}
	}

	repo.CreatedAt = existing.CreatedAt // preserve immutable field
	repo.UpdatedAt = time.Now().UTC()
	data, err := marshalToMap(repo)
	if err != nil {
		return fmt.Errorf("marshaling cached repository: %w", err)
	}
	if err := s.kvWrite(ctx, "cached-repos/"+repo.ID, data); err != nil {
		return err
	}

	if ownerNameChanged {
		// Delete old index entry, write new one.
		_ = s.kvDelete(ctx, fmt.Sprintf("cached-repos/by-owner-name/%s/%s", existing.Owner, existing.Name))
		return s.kvWrite(ctx, fmt.Sprintf("cached-repos/by-owner-name/%s/%s", repo.Owner, repo.Name), map[string]interface{}{
			"id": repo.ID,
		})
	}
	return nil
}

func (s *VaultStore) DeleteCachedRepository(ctx context.Context, id string) error {
	existing, err := s.GetCachedRepositoryByID(ctx, id)
	if err != nil {
		return err
	}
	if existing == nil {
		return fmt.Errorf("cached repository %s: %w", id, ErrNotFound)
	}
	// Delete the owner/name index entry.
	_ = s.kvDelete(ctx, fmt.Sprintf("cached-repos/by-owner-name/%s/%s", existing.Owner, existing.Name))
	return s.kvDelete(ctx, "cached-repos/"+id)
}

// --- Sessions ---

func (s *VaultStore) CreateSession(ctx context.Context, sess *Session) error {
	if sess.TokenHash == "" {
		return fmt.Errorf("CreateSession: TokenHash required")
	}
	if sess.CreatedAt.IsZero() {
		sess.CreatedAt = time.Now().UTC()
	}
	data, err := marshalToMap(sess)
	if err != nil {
		return fmt.Errorf("marshaling session: %w", err)
	}
	return s.kvWrite(ctx, "sessions/"+sess.TokenHash, data)
}

func (s *VaultStore) GetSessionByTokenHash(ctx context.Context, tokenHash string) (*Session, error) {
	data, err := s.kvRead(ctx, "sessions/"+tokenHash)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("session: %w", ErrNotFound)
	}
	var sess Session
	if err := unmarshalFromMap(data, &sess); err != nil {
		return nil, err
	}
	if !sess.ExpiresAt.IsZero() && time.Now().After(sess.ExpiresAt) {
		return nil, fmt.Errorf("session: %w", ErrNotFound)
	}
	return &sess, nil
}

func (s *VaultStore) DeleteSession(ctx context.Context, tokenHash string) error {
	return s.kvDelete(ctx, "sessions/"+tokenHash)
}

// DeleteExpiredSessions iterates the sessions/ prefix and deletes anything
// past its expiry. Vault has no list-with-filter, so this fans out one Read
// per row. Acceptable because cleanup runs infrequently — the auth handler
// invokes it on a fixed cadence (see authStateCleanupInterval in the auth
// package, currently 5 minutes).
func (s *VaultStore) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	keys, err := s.kvList(ctx, "sessions")
	if err != nil {
		return 0, err
	}
	now := time.Now()
	var deleted int64
	for _, k := range keys {
		data, err := s.kvRead(ctx, "sessions/"+k)
		if err != nil {
			return deleted, err
		}
		if data == nil {
			continue
		}
		var sess Session
		if err := unmarshalFromMap(data, &sess); err != nil {
			continue
		}
		if !sess.ExpiresAt.IsZero() && now.After(sess.ExpiresAt) {
			if err := s.kvDelete(ctx, "sessions/"+k); err != nil {
				return deleted, err
			}
			deleted++
		}
	}
	return deleted, nil
}

// --- OAuth states ---

func (s *VaultStore) CreateOAuthState(ctx context.Context, st *OAuthState) error {
	if st.State == "" {
		return fmt.Errorf("CreateOAuthState: State required")
	}
	if st.Kind != OAuthStateKindLogin && st.Kind != OAuthStateKindBroker {
		return fmt.Errorf("CreateOAuthState: invalid Kind %q", st.Kind)
	}
	if st.CreatedAt.IsZero() {
		st.CreatedAt = time.Now().UTC()
	}
	data, err := marshalToMap(st)
	if err != nil {
		return fmt.Errorf("marshaling oauth_state: %w", err)
	}
	return s.kvWrite(ctx, "oauth-states/"+st.State, data)
}

// ConsumeOAuthState reads then deletes. Vault KV does not support atomic
// read-and-delete, so a duplicate concurrent callback could in principle
// receive the same state twice. The window is bounded by the time between
// the kvRead and kvDelete here (typically single-digit ms), and the state
// payload itself is non-secret — at worst a duplicate browser session
// would race to consume the same row. Documented in CLAUDE.md as the
// Vault read-modify-write trade-off.
func (s *VaultStore) ConsumeOAuthState(ctx context.Context, state, kind string) (*OAuthState, error) {
	data, err := s.kvRead(ctx, "oauth-states/"+state)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("oauth_state: %w", ErrNotFound)
	}
	var st OAuthState
	if err := unmarshalFromMap(data, &st); err != nil {
		return nil, err
	}
	if st.Kind != kind {
		return nil, fmt.Errorf("oauth_state: %w", ErrNotFound)
	}
	if !st.ExpiresAt.IsZero() && time.Now().After(st.ExpiresAt) {
		_ = s.kvDelete(ctx, "oauth-states/"+state)
		return nil, fmt.Errorf("oauth_state: %w", ErrNotFound)
	}
	if err := s.kvDelete(ctx, "oauth-states/"+state); err != nil {
		return nil, err
	}
	return &st, nil
}

func (s *VaultStore) DeleteExpiredOAuthStates(ctx context.Context) (int64, error) {
	keys, err := s.kvList(ctx, "oauth-states")
	if err != nil {
		return 0, err
	}
	now := time.Now()
	var deleted int64
	for _, k := range keys {
		data, err := s.kvRead(ctx, "oauth-states/"+k)
		if err != nil {
			return deleted, err
		}
		if data == nil {
			continue
		}
		var st OAuthState
		if err := unmarshalFromMap(data, &st); err != nil {
			continue
		}
		if !st.ExpiresAt.IsZero() && now.After(st.ExpiresAt) {
			if err := s.kvDelete(ctx, "oauth-states/"+k); err != nil {
				return deleted, err
			}
			deleted++
		}
	}
	return deleted, nil
}

// --- Device authorization ---

func (s *VaultStore) CreateDeviceAuth(ctx context.Context, da *DeviceAuth) error {
	if da.DeviceCode == "" || da.UserCode == "" {
		return fmt.Errorf("CreateDeviceAuth: DeviceCode and UserCode required")
	}
	if da.Status == "" {
		da.Status = DeviceAuthStatusPending
	}
	if da.CreatedAt.IsZero() {
		da.CreatedAt = time.Now().UTC()
	}
	data, err := marshalToMap(da)
	if err != nil {
		return fmt.Errorf("marshaling device_auth: %w", err)
	}
	// Use KV v2 check-and-set (cas=0) for both writes so duplicate
	// device_code or user_code values are rejected atomically. SQL backends
	// rely on UNIQUE indexes for this guarantee; Vault has no equivalent
	// constraint, but `cas: 0` provides per-key create-only semantics, which
	// is enough when both keys are written together.
	if err := s.kvCreate(ctx, "device-auth/"+da.DeviceCode, data); err != nil {
		if errors.Is(err, errKVAlreadyExists) {
			return fmt.Errorf("device_code already in use")
		}
		return err
	}
	// Index user_code -> device_code for the verification page lookup.
	if err := s.kvCreate(ctx, "device-auth/by-user-code/"+da.UserCode, map[string]interface{}{
		"device_code": da.DeviceCode,
	}); err != nil {
		// Roll back the primary record if the user_code index conflicts so
		// we don't leave an orphan device-auth row pointing at a user_code
		// that resolves to someone else.
		if delErr := s.kvDelete(ctx, "device-auth/"+da.DeviceCode); delErr != nil {
			// Best-effort; the cleanup goroutine will eventually purge it.
			_ = delErr
		}
		if errors.Is(err, errKVAlreadyExists) {
			return fmt.Errorf("user_code already in use")
		}
		return err
	}
	return nil
}

func (s *VaultStore) GetDeviceAuthByDeviceCode(ctx context.Context, deviceCode string) (*DeviceAuth, error) {
	data, err := s.kvRead(ctx, "device-auth/"+deviceCode)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fmt.Errorf("device_auth: %w", ErrNotFound)
	}
	var da DeviceAuth
	if err := unmarshalFromMap(data, &da); err != nil {
		return nil, err
	}
	if !da.ExpiresAt.IsZero() && time.Now().After(da.ExpiresAt) {
		return nil, fmt.Errorf("device_auth: %w", ErrNotFound)
	}
	return &da, nil
}

func (s *VaultStore) GetDeviceAuthByUserCode(ctx context.Context, userCode string) (*DeviceAuth, error) {
	idx, err := s.kvRead(ctx, "device-auth/by-user-code/"+userCode)
	if err != nil {
		return nil, err
	}
	if idx == nil {
		return nil, fmt.Errorf("device_auth: %w", ErrNotFound)
	}
	deviceCode, _ := idx["device_code"].(string)
	if deviceCode == "" {
		return nil, fmt.Errorf("device_auth: %w", ErrNotFound)
	}
	return s.GetDeviceAuthByDeviceCode(ctx, deviceCode)
}

func (s *VaultStore) UpdateDeviceAuth(ctx context.Context, da *DeviceAuth) error {
	existing, err := s.kvRead(ctx, "device-auth/"+da.DeviceCode)
	if err != nil {
		return err
	}
	if existing == nil {
		return fmt.Errorf("device_auth %s: %w", da.DeviceCode, ErrNotFound)
	}
	data, err := marshalToMap(da)
	if err != nil {
		return fmt.Errorf("marshaling device_auth: %w", err)
	}
	return s.kvWrite(ctx, "device-auth/"+da.DeviceCode, data)
}

func (s *VaultStore) DeleteDeviceAuth(ctx context.Context, deviceCode string) error {
	// Delete the user_code index too. Best-effort: if the primary record
	// is gone the index is harmless and will be cleaned up on TTL.
	if data, err := s.kvRead(ctx, "device-auth/"+deviceCode); err == nil && data != nil {
		var da DeviceAuth
		if err := unmarshalFromMap(data, &da); err == nil && da.UserCode != "" {
			_ = s.kvDelete(ctx, "device-auth/by-user-code/"+da.UserCode)
		}
	}
	return s.kvDelete(ctx, "device-auth/"+deviceCode)
}

// DeleteExpiredDeviceAuths iterates device-auth/ and deletes expired records
// along with their user_code indexes. by-user-code/ entries that point at
// missing primary records are also pruned.
func (s *VaultStore) DeleteExpiredDeviceAuths(ctx context.Context) (int64, error) {
	keys, err := s.kvList(ctx, "device-auth")
	if err != nil {
		return 0, err
	}
	now := time.Now()
	var deleted int64
	for _, k := range keys {
		// Skip the index sub-prefix; we'll prune dangling entries below.
		if k == "by-user-code" {
			continue
		}
		data, err := s.kvRead(ctx, "device-auth/"+k)
		if err != nil {
			return deleted, err
		}
		if data == nil {
			continue
		}
		var da DeviceAuth
		if err := unmarshalFromMap(data, &da); err != nil {
			continue
		}
		if !da.ExpiresAt.IsZero() && now.After(da.ExpiresAt) {
			if da.UserCode != "" {
				_ = s.kvDelete(ctx, "device-auth/by-user-code/"+da.UserCode)
			}
			if err := s.kvDelete(ctx, "device-auth/"+k); err != nil {
				return deleted, err
			}
			deleted++
		}
	}
	// Prune dangling user_code index entries (records deleted directly,
	// e.g. by the polling endpoint).
	idxKeys, err := s.kvList(ctx, "device-auth/by-user-code")
	if err == nil {
		for _, idxKey := range idxKeys {
			idx, err := s.kvRead(ctx, "device-auth/by-user-code/"+idxKey)
			if err != nil || idx == nil {
				continue
			}
			deviceCode, _ := idx["device_code"].(string)
			if deviceCode == "" {
				_ = s.kvDelete(ctx, "device-auth/by-user-code/"+idxKey)
				continue
			}
			if primary, _ := s.kvRead(ctx, "device-auth/"+deviceCode); primary == nil {
				_ = s.kvDelete(ctx, "device-auth/by-user-code/"+idxKey)
			}
		}
	}
	return deleted, nil
}

// Ensure VaultStore implements Store.
var _ Store = (*VaultStore)(nil)
