package database

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	vault "github.com/hashicorp/vault/api"
)

// Supported Vault auth methods for the ghp database backend.
const (
	VaultAuthMethodAppRole    = "approle"
	VaultAuthMethodKubernetes = "kubernetes"

	// DefaultK8sAuthMount is the conventional auth mount path for the
	// Vault kubernetes auth backend.
	DefaultK8sAuthMount = "kubernetes"
	// DefaultK8sTokenPath is the standard path to the projected service
	// account token inside a pod.
	DefaultK8sTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// VaultStore implements Store using HashiCorp Vault KV v2 secrets engine.
type VaultStore struct {
	client    *vault.Client
	mountPath string // KV v2 mount path, e.g. "secret"
	basePath  string // prefix within the mount, e.g. "ghp"

	// Authentication parameters retained for re-login on token expiry.
	authMethod string // "approle" or "kubernetes"

	// AppRole fields (used when authMethod == "approle").
	roleID   string
	secretID string

	// Kubernetes fields (used when authMethod == "kubernetes").
	k8sRole      string
	k8sMount     string
	k8sTokenPath string
}

// VaultConfig holds configuration for Vault connectivity.
type VaultConfig struct {
	Addr      string // Vault server address
	MountPath string // KV v2 mount path (default: "secret")
	BasePath  string // key prefix (default: "ghp")

	// AuthMethod selects how ghp authenticates to Vault. Valid values:
	// "approle" (default) and "kubernetes". An empty string is treated as
	// "approle" for backwards compatibility.
	AuthMethod string

	// AppRole credentials. Required when AuthMethod is "approle".
	RoleID   string
	SecretID string

	// Kubernetes auth fields. Required when AuthMethod is "kubernetes".
	// K8sRole is the Vault role to authenticate as.
	// K8sMount is the auth mount path (default: "kubernetes").
	// K8sTokenPath is the path to the projected service account JWT
	// (default: /var/run/secrets/kubernetes.io/serviceaccount/token).
	K8sRole      string
	K8sMount     string
	K8sTokenPath string
}

// NewVaultStore creates a VaultStore authenticated to Vault using the
// configured auth method (AppRole by default, or kubernetes auth when
// requested).
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

	authMethod := cfg.AuthMethod
	if authMethod == "" {
		authMethod = VaultAuthMethodAppRole
	}

	store := &VaultStore{
		client:       client,
		mountPath:    mountPath,
		basePath:     basePath,
		authMethod:   authMethod,
		roleID:       cfg.RoleID,
		secretID:     cfg.SecretID,
		k8sRole:      cfg.K8sRole,
		k8sMount:     cfg.K8sMount,
		k8sTokenPath: cfg.K8sTokenPath,
	}

	switch authMethod {
	case VaultAuthMethodAppRole:
		if store.roleID == "" {
			return nil, fmt.Errorf("vault approle auth: role_id is required")
		}
		if store.secretID == "" {
			return nil, fmt.Errorf("vault approle auth: secret_id is required")
		}
	case VaultAuthMethodKubernetes:
		if store.k8sRole == "" {
			return nil, fmt.Errorf("vault kubernetes auth: role is required")
		}
		if store.k8sMount == "" {
			store.k8sMount = DefaultK8sAuthMount
		} else {
			normalized := strings.Trim(strings.TrimSpace(store.k8sMount), "/")
			if normalized == "" {
				return nil, fmt.Errorf("vault kubernetes auth: mount path %q is invalid", store.k8sMount)
			}
			store.k8sMount = normalized
		}
		if store.k8sTokenPath == "" {
			store.k8sTokenPath = DefaultK8sTokenPath
		}
	default:
		return nil, fmt.Errorf("unsupported vault auth method: %q (valid: %q, %q)",
			authMethod, VaultAuthMethodAppRole, VaultAuthMethodKubernetes)
	}

	if err := store.login(ctx); err != nil {
		return nil, fmt.Errorf("vault %s login: %w", authMethod, err)
	}

	return store, nil
}

// login authenticates to Vault using the configured auth method. It is
// safe to call repeatedly; each call replaces the current token.
//
// For the kubernetes method, the JWT file is re-read on every call so
// projected service-account tokens that were rotated by the kubelet are
// picked up automatically when the previous Vault token expires.
func (s *VaultStore) login(ctx context.Context) error {
	switch s.authMethod {
	case VaultAuthMethodKubernetes:
		return s.loginKubernetes(ctx)
	case VaultAuthMethodAppRole, "":
		return s.loginAppRole(ctx)
	default:
		return fmt.Errorf("unsupported vault auth method: %q", s.authMethod)
	}
}

func (s *VaultStore) loginAppRole(ctx context.Context) error {
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

func (s *VaultStore) loginKubernetes(ctx context.Context) error {
	jwt, err := os.ReadFile(s.k8sTokenPath)
	if err != nil {
		return fmt.Errorf("reading service account token from %s: %w", s.k8sTokenPath, err)
	}
	jwtStr := strings.TrimSpace(string(jwt))
	if jwtStr == "" {
		return fmt.Errorf("service account token at %s is empty", s.k8sTokenPath)
	}

	loginPath := fmt.Sprintf("auth/%s/login", s.k8sMount)
	loginResp, err := s.client.Logical().WriteWithContext(ctx, loginPath, map[string]interface{}{
		"role": s.k8sRole,
		"jwt":  jwtStr,
	})
	if err != nil {
		return fmt.Errorf("kubernetes login: %w", err)
	}
	if loginResp == nil || loginResp.Auth == nil {
		return fmt.Errorf("kubernetes login returned no auth token")
	}
	s.client.SetToken(loginResp.Auth.ClientToken)
	return nil
}

// withRelogin executes fn; if fn returns a 403 (expired/invalid token) it
// re-authenticates once using the configured Vault auth method and retries.
// This transparently handles Vault tokens that expire during the server's
// lifetime, regardless of whether AppRole or kubernetes auth is in use.
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
			// Surface both the 403 that triggered the re-login and the
			// re-authentication failure itself. With kubernetes auth, the
			// inner error is often the actionable one (e.g. "service
			// account token at /var/run/... is empty") and would otherwise
			// be hidden behind the original "permission denied".
			return fmt.Errorf("vault re-authentication after 403 failed: %w (original error: %v)", reloginErr, err)
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

// Ensure VaultStore implements Store.
var _ Store = (*VaultStore)(nil)
