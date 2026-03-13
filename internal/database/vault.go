package database

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
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
func NewVaultStore(cfg VaultConfig) (*VaultStore, error) {
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = cfg.Addr

	client, err := vault.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("creating vault client: %w", err)
	}

	// Authenticate via AppRole.
	loginResp, err := client.Logical().Write("auth/approle/login", map[string]interface{}{
		"role_id":   cfg.RoleID,
		"secret_id": cfg.SecretID,
	})
	if err != nil {
		return nil, fmt.Errorf("vault approle login: %w", err)
	}
	if loginResp == nil || loginResp.Auth == nil {
		return nil, fmt.Errorf("vault approle login returned no auth token")
	}
	client.SetToken(loginResp.Auth.ClientToken)

	mountPath := cfg.MountPath
	if mountPath == "" {
		mountPath = "secret"
	}
	basePath := cfg.BasePath
	if basePath == "" {
		basePath = "ghp"
	}

	return &VaultStore{
		client:    client,
		mountPath: mountPath,
		basePath:  basePath,
	}, nil
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

// kvWrite writes data to a KV v2 path.
func (s *VaultStore) kvWrite(ctx context.Context, key string, data map[string]interface{}) error {
	_, err := s.client.Logical().WriteWithContext(ctx, s.dataPath(key), map[string]interface{}{
		"data": data,
	})
	return err
}

// kvRead reads data from a KV v2 path. Returns nil, nil if not found.
func (s *VaultStore) kvRead(ctx context.Context, key string) (map[string]interface{}, error) {
	secret, err := s.client.Logical().ReadWithContext(ctx, s.dataPath(key))
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, nil
	}
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		return nil, nil
	}
	return data, nil
}

// kvDelete deletes a secret at the given path (destroys all versions via metadata).
func (s *VaultStore) kvDelete(ctx context.Context, key string) error {
	_, err := s.client.Logical().DeleteWithContext(ctx, s.metadataPath(key))
	return err
}

// kvList lists keys at the given path prefix. Returns nil if empty.
func (s *VaultStore) kvList(ctx context.Context, key string) ([]string, error) {
	secret, err := s.client.Logical().ListWithContext(ctx, s.metadataPath(key))
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
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
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
		return fmt.Errorf("app not found")
	}
	app.UpdatedAt = time.Now().UTC()
	data, err := marshalToMap(app)
	if err != nil {
		return fmt.Errorf("marshaling app: %w", err)
	}
	return s.kvWrite(ctx, "apps/"+app.ID, data)
}

func (s *VaultStore) DeleteApp(ctx context.Context, id string) error {
	existing, err := s.GetAppByID(ctx, id)
	if err != nil {
		return err
	}
	if existing == nil {
		return fmt.Errorf("app not found")
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
		token.TokenType = "proxy"
	}

	data, err := marshalToMap(token)
	if err != nil {
		return fmt.Errorf("marshaling proxy token: %w", err)
	}
	// Store the token hash in vault data since it's excluded from JSON via json:"-".
	data["token_hash"] = token.TokenHash

	if err := s.kvWrite(ctx, "proxy-tokens/"+token.ID, data); err != nil {
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
	// Handle request_count which may come back as json.Number or float64.
	if rc, ok := data["request_count"]; ok {
		switch v := rc.(type) {
		case float64:
			token.RequestCount = int64(v)
		case json.Number:
			n, _ := v.Int64()
			token.RequestCount = n
		case string:
			n, _ := strconv.ParseInt(v, 10, 64)
			token.RequestCount = n
		}
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
		if t.RevokedAt == nil && t.ExpiresAt.After(now) {
			active = append(active, t)
		}
	}
	return active, nil
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

	data, err := marshalToMap(token)
	if err != nil {
		return err
	}
	data["token_hash"] = token.TokenHash
	return s.kvWrite(ctx, "proxy-tokens/"+id, data)
}

func (s *VaultStore) UpdateProxyTokenUsage(ctx context.Context, id string) error {
	token, err := s.GetProxyTokenByID(ctx, id)
	if err != nil {
		return err
	}
	if token == nil {
		return nil
	}
	now := time.Now().UTC()
	token.LastUsedAt = &now
	token.RequestCount++

	data, err := marshalToMap(token)
	if err != nil {
		return err
	}
	data["token_hash"] = token.TokenHash
	return s.kvWrite(ctx, "proxy-tokens/"+id, data)
}

// Ensure VaultStore implements Store.
var _ Store = (*VaultStore)(nil)
