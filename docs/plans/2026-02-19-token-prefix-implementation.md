# Token Prefix Redesign Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace `ghp_` token prefix with `ghx_` for proxy tokens and add `gha_` prefix for app-scoped agent tokens.

**Architecture:** Extend the existing `ProxyToken` model with a `TokenType` discriminator and new nullable fields. Centralize prefix-to-type mapping in the token package. Branch resolution logic based on token type — proxy tokens use OAuth decrypt, agent tokens use GitHub App installation tokens.

**Tech Stack:** Go, SQLite (primary), PostgreSQL (migration schema only), Playwright (e2e)

**Design doc:** `docs/plans/2026-02-19-token-prefix-redesign.md`

---

### Task 1: Token Type Enum and Prefix Constants

**Files:**
- Modify: `internal/token/token.go:18-25`
- Modify: `internal/token/token_test.go`

**Step 1: Write the failing test**

Add to `internal/token/token_test.go`:

```go
func TestTokenTypeFromPrefix(t *testing.T) {
	tests := []struct {
		input    string
		wantType TokenType
		wantOK   bool
	}{
		{"ghx_abc123", TokenTypeProxy, true},
		{"gha_abc123", TokenTypeAgent, true},
		{"ghp_abc123", "", false},
		{"gho_abc123", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got, ok := TokenTypeFromPrefix(tt.input)
		if ok != tt.wantOK || got != tt.wantType {
			t.Errorf("TokenTypeFromPrefix(%q) = (%q, %v), want (%q, %v)",
				tt.input, got, ok, tt.wantType, tt.wantOK)
		}
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/token/ -run TestTokenTypeFromPrefix -v`
Expected: FAIL — `TokenTypeFromPrefix` undefined

**Step 3: Write the implementation**

Replace the constants block in `internal/token/token.go:18-25` with:

```go
// TokenType distinguishes proxy tokens from agent tokens.
type TokenType string

const (
	TokenTypeProxy TokenType = "proxy"
	TokenTypeAgent TokenType = "agent"
)

// Prefix constants for each token type.
const (
	PrefixProxy = "ghx_"
	PrefixAgent = "gha_"
	TokenBytes  = 32
	alphabet    = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// tokenPrefixes maps token types to their string prefixes.
var tokenPrefixes = map[TokenType]string{
	TokenTypeProxy: PrefixProxy,
	TokenTypeAgent: PrefixAgent,
}

// TokenTypeFromPrefix returns the token type for a given prefixed string.
func TokenTypeFromPrefix(s string) (TokenType, bool) {
	for tt, prefix := range tokenPrefixes {
		if strings.HasPrefix(s, prefix) {
			return tt, true
		}
	}
	return "", false
}

// PrefixForType returns the prefix for a given token type.
func PrefixForType(tt TokenType) string {
	return tokenPrefixes[tt]
}
```

Remove the old `Prefix` constant. Update the package doc comment from `ghp_` to describe both types.

**Step 4: Fix all references to the old `Prefix` constant**

In `internal/token/token.go`:
- `generateToken()` → `generateToken(tt TokenType)`, use `PrefixForType(tt)` instead of `Prefix`
- `Resolve()` → use `TokenTypeFromPrefix()` instead of `strings.HasPrefix(plaintext, Prefix)`
- `Create()` → pass `TokenTypeProxy` to `generateToken` (for now, agent creation comes in Task 5)
- Update doc comments referencing `ghp_`

In `internal/token/token_test.go`:
- `TestGenerateToken` → update to call `generateToken(TokenTypeProxy)` and check `PrefixProxy`
- `TestHash` → change `"ghp_testtoken1"` / `"ghp_testtoken2"` to `"ghx_testtoken1"` / `"ghx_testtoken2"` (hash function is prefix-agnostic, but update for consistency)

**Step 5: Run tests**

Run: `go test ./internal/token/ -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/token/token.go internal/token/token_test.go
git commit -m "feat: replace ghp_ prefix with ghx_/gha_ token type system"
```

---

### Task 2: Database Model and Migration Changes

**Files:**
- Modify: `internal/database/models.go:34-49`
- Modify: `internal/database/migrations/sqlite/001_initial.up.sql:23-37`
- Modify: `internal/database/migrations/postgres/001_initial.up.sql:25-39`
- Modify: `internal/database/sqlite.go:264-304` (CreateProxyToken, scanProxyToken)
- Modify: `internal/database/sqlite_test.go:96-184` (TestProxyTokenCRUD)

**Step 1: Write the failing test**

Update `TestProxyTokenCRUD` in `internal/database/sqlite_test.go` to use new fields:

```go
func TestProxyTokenCRUD(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	user := &User{GitHubID: 1, GitHubUsername: "bob", Role: "user"}
	if err := store.UpsertUser(ctx, user); err != nil {
		t.Fatal(err)
	}

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
	scopes := json.RawMessage(`{"contents":"read","pulls":"write"}`)
	repos := json.RawMessage(`["org/repo"]`)
	pt := &ProxyToken{
		TokenHash:     "sha256hash123",
		TokenPrefix:   "ghx_a1b2",
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

	got, err := store.GetProxyTokenByHash(ctx, "sha256hash123")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("expected token, got nil")
	}
	if got.TokenType != "proxy" {
		t.Errorf("token_type = %q, want proxy", got.TokenType)
	}
	if got.TokenPrefix != "ghx_a1b2" {
		t.Errorf("prefix = %q, want ghx_a1b2", got.TokenPrefix)
	}

	var gotRepos []string
	if err := json.Unmarshal(got.Repositories, &gotRepos); err != nil {
		t.Fatal(err)
	}
	if len(gotRepos) != 1 || gotRepos[0] != "org/repo" {
		t.Errorf("repositories = %v, want [org/repo]", gotRepos)
	}

	// Test agent token (gha_ type) with installation_id and no user/github_token.
	installID := int64(12345)
	agentRepos := json.RawMessage(`["org/repo1","org/repo2"]`)
	at := &ProxyToken{
		TokenHash:      "sha256hash456",
		TokenPrefix:    "gha_c3d4",
		TokenType:      "agent",
		UserID:         &user.ID, // admin who created it
		InstallationID: &installID,
		Repositories:   agentRepos,
		Scopes:         json.RawMessage(`{"contents":"read"}`),
		SessionID:      "admin-session",
		ExpiresAt:      time.Now().Add(365 * 24 * time.Hour),
	}
	if err := store.CreateProxyToken(ctx, at); err != nil {
		t.Fatal(err)
	}

	gotAgent, err := store.GetProxyTokenByHash(ctx, "sha256hash456")
	if err != nil {
		t.Fatal(err)
	}
	if gotAgent.TokenType != "agent" {
		t.Errorf("token_type = %q, want agent", gotAgent.TokenType)
	}
	if gotAgent.InstallationID == nil || *gotAgent.InstallationID != 12345 {
		t.Errorf("installation_id = %v, want 12345", gotAgent.InstallationID)
	}

	// Remaining CRUD tests (usage, list, revoke) — same as before but using new field names.
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

	tokens, err := store.ListProxyTokens(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 2 {
		t.Errorf("ListProxyTokens = %d, want 2", len(tokens))
	}

	if err := store.RevokeProxyToken(ctx, pt.ID); err != nil {
		t.Fatal(err)
	}
	got3, _ := store.GetProxyTokenByID(ctx, pt.ID)
	if got3.RevokedAt == nil {
		t.Error("revoked_at should be set")
	}
	if err := store.RevokeProxyToken(ctx, pt.ID); err == nil {
		t.Error("expected error on double revoke")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/database/ -run TestProxyTokenCRUD -v`
Expected: FAIL — fields don't exist on ProxyToken

**Step 3: Update the ProxyToken model**

In `internal/database/models.go`, replace the `ProxyToken` struct:

```go
// ProxyToken represents a ghx_ or gha_ token issued to agents.
type ProxyToken struct {
	ID             string          `json:"id"`
	TokenHash      string          `json:"-"`
	TokenPrefix    string          `json:"token_prefix"`
	TokenType      string          `json:"token_type"`
	UserID         *string         `json:"user_id,omitempty"`
	GitHubTokenID  *string         `json:"github_token_id,omitempty"`
	InstallationID *int64          `json:"installation_id,omitempty"`
	Repositories   json.RawMessage `json:"repositories"`
	Scopes         json.RawMessage `json:"scopes"`
	SessionID      string          `json:"session_id"`
	ExpiresAt      time.Time       `json:"expires_at"`
	RevokedAt      *time.Time      `json:"revoked_at,omitempty"`
	LastUsedAt     *time.Time      `json:"last_used_at,omitempty"`
	RequestCount   int64           `json:"request_count"`
	CreatedAt      time.Time       `json:"created_at"`
}
```

**Step 4: Rewrite migration 001 (SQLite)**

Replace `internal/database/migrations/sqlite/001_initial.up.sql` proxy_tokens table:

```sql
CREATE TABLE proxy_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    token_type TEXT NOT NULL DEFAULT 'proxy' CHECK (token_type IN ('proxy', 'agent')),
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    github_token_id TEXT REFERENCES github_tokens(id) ON DELETE CASCADE,
    installation_id INTEGER,
    repositories TEXT NOT NULL DEFAULT '[]',
    scopes TEXT NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    last_used_at TEXT,
    request_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
```

**Step 5: Rewrite migration 001 (PostgreSQL)**

Replace `internal/database/migrations/postgres/001_initial.up.sql` proxy_tokens table:

```sql
CREATE TYPE token_type AS ENUM ('proxy', 'agent');

CREATE TABLE proxy_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    token_type token_type NOT NULL DEFAULT 'proxy',
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    github_token_id UUID REFERENCES github_tokens(id) ON DELETE CASCADE,
    installation_id BIGINT,
    repositories JSONB NOT NULL DEFAULT '[]',
    scopes JSONB NOT NULL,
    session_id TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    request_count BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

Also update the PostgreSQL down migration (`001_initial.down.sql`) to drop the `token_type` enum:
Add `DROP TYPE IF EXISTS token_type;` after `DROP TABLE IF EXISTS proxy_tokens;`.

**Step 6: Update SQLite store CRUD**

In `internal/database/sqlite.go`, update `CreateProxyToken` to include new columns:

```go
func (s *SQLiteStore) CreateProxyToken(ctx context.Context, token *ProxyToken) error {
	if token.ID == "" {
		token.ID = uuid.New().String()
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	scopesJSON, err := json.Marshal(token.Scopes)
	if err != nil {
		return fmt.Errorf("marshaling scopes: %w", err)
	}
	reposJSON, err := json.Marshal(token.Repositories)
	if err != nil {
		return fmt.Errorf("marshaling repositories: %w", err)
	}
	tokenType := token.TokenType
	if tokenType == "" {
		tokenType = "proxy"
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO proxy_tokens (id, token_hash, token_prefix, token_type, user_id, github_token_id, installation_id, repositories, scopes, session_id, expires_at, request_count, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
	`, token.ID, token.TokenHash, token.TokenPrefix, tokenType, token.UserID, token.GitHubTokenID,
		token.InstallationID, string(reposJSON), string(scopesJSON), token.SessionID,
		token.ExpiresAt.Format(time.RFC3339Nano), now)
	return err
}
```

Update `scanProxyToken` to read new columns:

```go
func scanProxyToken(scan func(dest ...interface{}) error) (*ProxyToken, error) {
	t := &ProxyToken{}
	var scopesStr, reposStr string
	var revokedAt, lastUsedAt sql.NullString
	var expiresStr, createdStr string
	var userID, githubTokenID sql.NullString
	var installationID sql.NullInt64
	err := scan(&t.ID, &t.TokenHash, &t.TokenPrefix, &t.TokenType, &userID, &githubTokenID, &installationID, &reposStr, &scopesStr,
		&t.SessionID, &expiresStr, &revokedAt, &lastUsedAt, &t.RequestCount, &createdStr)
	if err != nil {
		return nil, err
	}
	t.Scopes = json.RawMessage(scopesStr)
	t.Repositories = json.RawMessage(reposStr)
	if userID.Valid {
		t.UserID = &userID.String
	}
	if githubTokenID.Valid {
		t.GitHubTokenID = &githubTokenID.String
	}
	if installationID.Valid {
		t.InstallationID = &installationID.Int64
	}
	t.ExpiresAt = parseTime(expiresStr)
	t.CreatedAt = parseTime(createdStr)
	if revokedAt.Valid {
		ts := parseTime(revokedAt.String)
		t.RevokedAt = &ts
	}
	if lastUsedAt.Valid {
		ts := parseTime(lastUsedAt.String)
		t.LastUsedAt = &ts
	}
	return t, nil
}
```

Update ALL SQL SELECT statements in `GetProxyTokenByHash`, `GetProxyTokenByID`, `ListProxyTokens`, `ListAllProxyTokens` to include the new columns in the same order as `scanProxyToken`:

```sql
SELECT id, token_hash, token_prefix, token_type, user_id, github_token_id, installation_id, repositories, scopes, session_id, expires_at, revoked_at, last_used_at, request_count, created_at
FROM proxy_tokens ...
```

**Step 7: Run tests**

Run: `go test ./internal/database/ -v`
Expected: PASS

**Step 8: Commit**

```bash
git add internal/database/models.go internal/database/sqlite.go internal/database/sqlite_test.go internal/database/migrations/sqlite/001_initial.up.sql internal/database/migrations/postgres/001_initial.up.sql internal/database/migrations/postgres/001_initial.down.sql
git commit -m "feat: add token_type, installation_id, repositories to proxy_tokens schema"
```

---

### Task 3: Token Service — Update Create and Resolve for Dual Prefix

**Files:**
- Modify: `internal/token/token.go:27-141`
- Modify: `internal/token/token_test.go`

**Step 1: Write the failing test**

Add to `internal/token/token_test.go`:

```go
func TestGenerateTokenProxy(t *testing.T) {
	tok, err := generateToken(TokenTypeProxy)
	if err != nil {
		t.Fatalf("generateToken(proxy) error: %v", err)
	}
	if !strings.HasPrefix(tok, PrefixProxy) {
		t.Errorf("proxy token should start with %q, got prefix %q", PrefixProxy, tok[:4])
	}
}

func TestGenerateTokenAgent(t *testing.T) {
	tok, err := generateToken(TokenTypeAgent)
	if err != nil {
		t.Fatalf("generateToken(agent) error: %v", err)
	}
	if !strings.HasPrefix(tok, PrefixAgent) {
		t.Errorf("agent token should start with %q, got prefix %q", PrefixAgent, tok[:4])
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/token/ -run TestGenerateToken -v`
Expected: FAIL — `generateToken` takes no arguments

**Step 3: Update token.go**

Update `CreateRequest` to include new fields:

```go
type CreateRequest struct {
	TokenType      TokenType
	UserID         string
	GitHubTokenID  string            // Required for proxy tokens.
	InstallationID int64             // Required for agent tokens.
	Repository     string            // Single repo — for proxy tokens.
	Repositories   []string          // Multi repo — for agent tokens.
	Scopes         map[string]string
	Duration       time.Duration
	SessionID      string
}
```

Update `CreateResult`:

```go
type CreateResult struct {
	Token        string
	ID           string
	TokenType    TokenType
	Repositories []string
	Scopes       map[string]string
	ExpiresAt    time.Time
	SessionID    string
}
```

Update `generateToken` to take a `TokenType`:

```go
func generateToken(tt TokenType) (string, error) {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	n := new(big.Int).SetBytes(b)
	base := big.NewInt(int64(len(alphabet)))
	var result []byte
	for n.Sign() > 0 {
		mod := new(big.Int)
		n.DivMod(n, base, mod)
		result = append(result, alphabet[mod.Int64()])
	}
	for len(result) < 43 {
		result = append(result, alphabet[0])
	}
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}
	return PrefixForType(tt) + string(result), nil
}
```

Update `Create` to handle both token types:

```go
func (s *Service) Create(ctx context.Context, req CreateRequest) (*CreateResult, error) {
	tt := req.TokenType
	if tt == "" {
		tt = TokenTypeProxy
	}

	// Build repositories list.
	var repos []string
	switch tt {
	case TokenTypeProxy:
		if req.Repository == "" {
			return nil, fmt.Errorf("repository is required for proxy tokens")
		}
		repos = []string{req.Repository}
	case TokenTypeAgent:
		if len(req.Repositories) == 0 {
			return nil, fmt.Errorf("at least one repository is required for agent tokens")
		}
		if req.InstallationID == 0 {
			return nil, fmt.Errorf("installation_id is required for agent tokens")
		}
		repos = req.Repositories
	default:
		return nil, fmt.Errorf("unknown token type %q", tt)
	}

	if len(req.Scopes) == 0 {
		return nil, fmt.Errorf("at least one scope is required")
	}
	if req.Duration <= 0 {
		return nil, fmt.Errorf("duration must be positive")
	}
	if req.Duration > s.maxDuration {
		return nil, fmt.Errorf("duration %s exceeds maximum %s", req.Duration, s.maxDuration)
	}

	plaintext, err := generateToken(tt)
	if err != nil {
		return nil, fmt.Errorf("generating token: %w", err)
	}

	hash := Hash(plaintext)
	prefix := plaintext[:8]

	scopesJSON, err := json.Marshal(req.Scopes)
	if err != nil {
		return nil, fmt.Errorf("marshaling scopes: %w", err)
	}

	reposJSON, err := json.Marshal(repos)
	if err != nil {
		return nil, fmt.Errorf("marshaling repositories: %w", err)
	}

	expiresAt := time.Now().UTC().Add(req.Duration)

	pt := &database.ProxyToken{
		TokenHash:    hash,
		TokenPrefix:  prefix,
		TokenType:    string(tt),
		Repositories: json.RawMessage(reposJSON),
		Scopes:       json.RawMessage(scopesJSON),
		SessionID:    req.SessionID,
		ExpiresAt:    expiresAt,
	}

	// Set type-specific fields.
	if req.UserID != "" {
		pt.UserID = &req.UserID
	}
	if req.GitHubTokenID != "" {
		pt.GitHubTokenID = &req.GitHubTokenID
	}
	if req.InstallationID != 0 {
		pt.InstallationID = &req.InstallationID
	}

	if err := s.store.CreateProxyToken(ctx, pt); err != nil {
		return nil, fmt.Errorf("storing token: %w", err)
	}

	return &CreateResult{
		Token:        plaintext,
		ID:           pt.ID,
		TokenType:    tt,
		Repositories: repos,
		Scopes:       req.Scopes,
		ExpiresAt:    expiresAt,
		SessionID:    req.SessionID,
	}, nil
}
```

Update `Resolve` to use `TokenTypeFromPrefix`:

```go
func (s *Service) Resolve(ctx context.Context, plaintext string) (*database.ProxyToken, error) {
	if _, ok := TokenTypeFromPrefix(plaintext); !ok {
		return nil, fmt.Errorf("invalid token prefix")
	}

	hash := Hash(plaintext)
	pt, err := s.store.GetProxyTokenByHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("looking up token: %w", err)
	}
	if pt == nil {
		return nil, nil
	}

	if pt.RevokedAt != nil {
		return nil, fmt.Errorf("token has been revoked")
	}
	if time.Now().After(pt.ExpiresAt) {
		return nil, fmt.Errorf("token has expired")
	}

	return pt, nil
}
```

**Step 4: Update the old TestGenerateToken**

Replace `TestGenerateToken` with `TestGenerateTokenProxy` and `TestGenerateTokenAgent` from Step 1. Remove the old test.

**Step 5: Run tests**

Run: `go test ./internal/token/ -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/token/token.go internal/token/token_test.go
git commit -m "feat: update token service for dual prefix and type-aware create/resolve"
```

---

### Task 4: Proxy Layer — Rename extractGhpToken and Fix Callers

**Files:**
- Modify: `internal/proxy/passthrough.go:17-207`
- Modify: `internal/proxy/proxy.go:52-145`
- Modify: `internal/proxy/resolver.go`
- Modify: `internal/proxy/passthrough_test.go`
- Modify: `internal/proxy/resolver_test.go`

**Step 1: Rename `extractGhpToken` → `extractClientToken`**

In `internal/proxy/passthrough.go`:
- Rename function at line 177
- Update doc comment
- Change `token.Prefix` references to use `token.TokenTypeFromPrefix` for detection:

```go
func extractClientToken(r *http.Request) (string, func(realToken string) string) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", nil
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 {
		return "", nil
	}
	scheme := strings.ToLower(parts[0])
	originalScheme := parts[0]
	credential := parts[1]
	if (scheme == "token" || scheme == "bearer") {
		if _, ok := token.TokenTypeFromPrefix(credential); ok {
			return credential, func(realToken string) string {
				return originalScheme + " " + realToken
			}
		}
	}
	if scheme == "basic" {
		decoded, err := base64.StdEncoding.DecodeString(credential)
		if err != nil {
			return "", nil
		}
		user, pass, ok := strings.Cut(string(decoded), ":")
		if ok && strings.EqualFold(user, "x-access-token") {
			if _, ok := token.TokenTypeFromPrefix(pass); ok {
				return pass, func(realToken string) string {
					return originalScheme + " " + base64.StdEncoding.EncodeToString([]byte(user+":"+realToken))
				}
			}
		}
	}
	return "", nil
}
```

**Step 2: Update all callers**

In `internal/proxy/passthrough.go`:
- Line 43: `extractGhpToken(req)` → `extractClientToken(req)`
- Line 78: `extractGhpToken(r)` → `extractClientToken(r)`

In `internal/proxy/proxy.go`:
- Line 74: `extractGhpToken(r)` → `extractClientToken(r)`
- Update all comments referencing `ghp_` tokens to reference `ghx_`/`gha_` or "client tokens"

**Step 3: Update doc comments on interfaces**

In `internal/proxy/passthrough.go`:
- `TokenResolver` doc: `ghp_` → "client token (ghx_/gha_)"
- `ScopeEnforcer` doc: `ghp_` → "client token"
- `NewPassthroughHandler` doc: `ghp_` → "client token (ghx_/gha_)"
- `NewScopedPassthroughHandler` doc: `ghp_` → "client token"

In `internal/proxy/resolver.go`:
- `ProxyTokenResolver` doc: `ghp_` → "client"
- `ResolveToGitHubToken` doc: `ghp_` → "client"

**Step 4: Update repository scope check for multi-repo**

In `internal/proxy/passthrough.go` `NewScopedPassthroughHandler`, line 106:
Replace `!strings.EqualFold(repo, pt.Repository)` with a helper that checks if the repo is in `pt.Repositories`:

```go
// Check repository scope.
if !repositoryAllowed(repo, pt.Repositories) {
    writeError(w, http.StatusForbidden,
        fmt.Sprintf("Token is not scoped to %s", repo))
    return
}
```

Add the helper:

```go
// repositoryAllowed returns true if the given repo is in the JSON array of repositories.
func repositoryAllowed(repo string, reposJSON json.RawMessage) bool {
	var repos []string
	if err := json.Unmarshal(reposJSON, &repos); err != nil {
		return false
	}
	for _, r := range repos {
		if strings.EqualFold(r, repo) {
			return true
		}
	}
	return false
}
```

Similarly in `internal/proxy/proxy.go` line 102, replace:
```go
if repo != "" && !strings.EqualFold(repo, pt.Repository) {
```
with:
```go
if repo != "" && !repositoryAllowed(repo, pt.Repositories) {
```

Update the error message format to not reference a single repository.

**Step 5: Update proxy.go `getGitHubToken` for pointer fields**

In `internal/proxy/proxy.go` `getGitHubToken`, line 167:
`pt.GitHubTokenID` is now `*string`. Update:

```go
func (h *Handler) getGitHubToken(r *http.Request, pt *database.ProxyToken) (string, error) {
	if pt.GitHubTokenID == nil {
		return "", fmt.Errorf("token has no linked GitHub credential")
	}
	gt, err := h.store.GetGitHubTokenByID(r.Context(), *pt.GitHubTokenID)
	// ... rest unchanged
}
```

**Step 6: Update proxy.go `logRequest` for pointer fields**

In `internal/proxy/proxy.go` `logRequest`, line 410:
`pt.UserID` is now `*string`. Update the logger and audit entry to dereference:

```go
func (h *Handler) logRequest(ctx context.Context, pt *database.ProxyToken, method, path, repo string, status int, dur time.Duration, action string) {
	userID := ""
	if pt.UserID != nil {
		userID = *pt.UserID
	}
	h.logger.Info(action,
		"token_id", pt.ID,
		"user_id", userID,
		// ...
	)

	entry := &database.AuditEntry{
		UserID: userID,
		// ...
	}
	// ...
}
```

**Step 7: Update resolver.go for pointer fields**

In `internal/proxy/resolver.go` `ResolveToGitHubToken`:

```go
func (r *ProxyTokenResolver) ResolveToGitHubToken(ctx context.Context, clientToken string) (string, error) {
	pt, err := r.tokenService.Resolve(ctx, clientToken)
	if err != nil {
		return "", fmt.Errorf("resolving token: %w", err)
	}
	if pt == nil {
		return "", fmt.Errorf("invalid token")
	}
	if pt.GitHubTokenID == nil {
		return "", fmt.Errorf("token has no linked GitHub credential")
	}

	gt, err := r.store.GetGitHubTokenByID(ctx, *pt.GitHubTokenID)
	// ... rest unchanged
}
```

**Step 8: Update tests**

In `internal/proxy/passthrough_test.go`:
- Update `token.Prefix` → `token.PrefixProxy` on line 58
- Update all comments referencing `ghp_` to `ghx_`

In `internal/proxy/resolver_test.go`:
- Line 83: `"ghp_nonexistenttoken1234567890abcdefghijklmno"` → `"ghx_nonexistenttoken1234567890abcdefghijklmno"`
- Update `CreateRequest` calls to use new field names

In `internal/proxy/passthrough_test.go` `newScopedPassthrough`:
- `Repository: repo` → `Repository: repo` (the `CreateRequest` still has a `Repository` field for proxy tokens)
- Update the test to account for `UserID` and `GitHubTokenID` now being pointers in assertions

**Step 9: Run tests**

Run: `go test ./internal/proxy/ -v`
Expected: PASS

**Step 10: Commit**

```bash
git add internal/proxy/passthrough.go internal/proxy/proxy.go internal/proxy/resolver.go internal/proxy/passthrough_test.go internal/proxy/resolver_test.go
git commit -m "feat: rename extractGhpToken to extractClientToken, support dual prefix detection"
```

---

### Task 5: API Layer — Update Token Create Endpoint

**Files:**
- Modify: `internal/server/api.go:50-123`

**Step 1: Update `createTokenRequest` struct**

```go
type createTokenRequest struct {
	Type           string   `json:"type"`            // "proxy" (default) or "agent"
	Repository     string   `json:"repository"`      // For proxy tokens.
	Repositories   []string `json:"repositories"`    // For agent tokens.
	InstallationID int64    `json:"installation_id"` // For agent tokens.
	Scopes         string   `json:"scopes"`
	Duration       string   `json:"duration"`
	SessionID      string   `json:"session_id"`
}
```

**Step 2: Update `handleCreateToken`**

```go
func (a *API) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	session := auth.SessionFromContext(r.Context())

	var req createTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid request body"})
		return
	}

	tt := token.TokenTypeProxy
	if req.Type == "agent" {
		tt = token.TokenTypeAgent
		// Agent tokens require admin role.
		if session.Role != "admin" {
			writeJSON(w, http.StatusForbidden, map[string]string{"message": "Admin role required for agent tokens"})
			return
		}
	}

	scopes, err := token.ParseScopeString(req.Scopes)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}

	duration := a.cfg.Tokens.DefaultDuration
	if req.Duration != "" {
		d, err := time.ParseDuration(req.Duration)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "Invalid duration format"})
			return
		}
		duration = d
	}

	createReq := token.CreateRequest{
		TokenType:  tt,
		UserID:     session.UserID,
		Scopes:     scopes,
		Duration:   duration,
		SessionID:  req.SessionID,
	}

	switch tt {
	case token.TokenTypeProxy:
		gt, err := a.store.GetGitHubToken(r.Context(), session.UserID)
		if err != nil || gt == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"message": "No GitHub token found. Please re-authenticate."})
			return
		}
		createReq.GitHubTokenID = gt.ID
		createReq.Repository = req.Repository
	case token.TokenTypeAgent:
		createReq.InstallationID = req.InstallationID
		createReq.Repositories = req.Repositories
	}

	result, err := a.tokenService.Create(r.Context(), createReq)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}

	a.store.CreateAuditEntry(r.Context(), &database.AuditEntry{
		UserID:    session.UserID,
		Action:    "token_created",
		SessionID: req.SessionID,
	})

	a.logger.Info("token_created",
		"user", session.Username,
		"type", string(tt),
		"repos", result.Repositories,
		"session", req.SessionID,
	)

	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"token":        result.Token,
		"id":           result.ID,
		"type":         string(result.TokenType),
		"repositories": result.Repositories,
		"scopes":       result.Scopes,
		"expires_at":   result.ExpiresAt.Format(time.RFC3339),
		"session_id":   result.SessionID,
	})
}
```

**Step 3: Update `handleGetToken` and `handleRevokeToken` for pointer UserID**

In both handlers, change `pt.UserID != session.UserID` to:
```go
if (pt.UserID == nil || *pt.UserID != session.UserID) && session.Role != "admin" {
```

**Step 4: Run tests**

Run: `go test ./internal/server/ -v`
Run: `go test ./... -v` (full suite)
Expected: PASS

**Step 5: Commit**

```bash
git add internal/server/api.go
git commit -m "feat: update token create API for dual token types"
```

---

### Task 6: App Credential Configuration

**Files:**
- Modify: `internal/config/config.go:43-49`

**Step 1: Verify existing config**

The `GitHubConfig` already has `AppID`, `ClientID`, `ClientSecret`, `PrivateKeyFile`. The `AppID` and `PrivateKeyFile` fields already exist! They're likely used for webhook verification or similar. Confirm they can be reused for `gha_` token flow.

If they're already present and wired to env vars via the `GHP_GITHUB_` prefix, no config changes are needed — just document that `GHP_GITHUB_APP_ID` and `GHP_GITHUB_PRIVATE_KEY_FILE` power the `gha_` flow.

**Step 2: Add PEM content env var support (if PrivateKey field doesn't exist)**

If only `PrivateKeyFile` exists (file path), add a `PrivateKey` field for inline PEM:

```go
type GitHubConfig struct {
	AppID          int64  `koanf:"app_id"`
	ClientID       string `koanf:"client_id"`
	ClientSecret   string `koanf:"client_secret"`
	PrivateKey     string `koanf:"private_key"`      // PEM contents directly
	PrivateKeyFile string `koanf:"private_key_file"`  // Path to PEM file
	EnterpriseSlug string `koanf:"enterprise_slug"`
}
```

This maps to env var `GHP_GITHUB_PRIVATE_KEY`.

**Step 3: Commit**

```bash
git add internal/config/config.go
git commit -m "feat: add inline private_key config for GitHub App PEM"
```

---

### Task 7: AppTokenProvider — Installation Token Generation

**Files:**
- Create: `internal/github/app.go`
- Create: `internal/github/app_test.go`

**Step 1: Write the failing test**

Create `internal/github/app_test.go`:

```go
package github

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAppTokenProvider_GetInstallationToken(t *testing.T) {
	// Mock GitHub API that returns an installation token.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations/123/access_tokens" && r.Method == "POST" {
			// Verify JWT auth header is present.
			auth := r.Header.Get("Authorization")
			if auth == "" {
				t.Error("expected Authorization header")
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "ghs_testinstallationtoken",
				"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	// Use a test RSA key.
	provider, err := NewAppTokenProvider(AppConfig{
		AppID:      1,
		PrivateKey: testRSAKey,
		BaseURL:    server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	token, err := provider.GetInstallationToken(context.Background(), 123, []string{"org/repo"}, map[string]string{"contents": "read"})
	if err != nil {
		t.Fatal(err)
	}
	if token != "ghs_testinstallationtoken" {
		t.Errorf("expected ghs_testinstallationtoken, got %q", token)
	}
}

// testRSAKey is a test-only RSA private key in PEM format.
// Generated with: openssl genrsa 2048
var testRSAKey = `-----BEGIN RSA PRIVATE KEY-----
... (generate a real test key during implementation)
-----END RSA PRIVATE KEY-----`
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/github/ -run TestAppTokenProvider -v`
Expected: FAIL — package doesn't exist

**Step 3: Implement AppTokenProvider**

Create `internal/github/app.go`:

```go
package github

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AppConfig holds configuration for GitHub App authentication.
type AppConfig struct {
	AppID      int64
	PrivateKey string // PEM-encoded RSA private key
	BaseURL    string // GitHub API base URL, defaults to https://api.github.com
}

// AppTokenProvider generates GitHub App installation tokens.
type AppTokenProvider struct {
	appID   int64
	key     *rsa.PrivateKey
	baseURL string
	client  *http.Client
	mu      sync.Mutex
	cache   map[int64]cachedToken
}

type cachedToken struct {
	token     string
	expiresAt time.Time
}

// NewAppTokenProvider creates a provider from the given config.
func NewAppTokenProvider(cfg AppConfig) (*AppTokenProvider, error) {
	block, _ := pem.Decode([]byte(cfg.PrivateKey))
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}
	baseURL := cfg.BaseURL
	if baseURL == "" {
		baseURL = "https://api.github.com"
	}
	return &AppTokenProvider{
		appID:   cfg.AppID,
		key:     key,
		baseURL: baseURL,
		client:  &http.Client{Timeout: 30 * time.Second},
		cache:   make(map[int64]cachedToken),
	}, nil
}

// GetInstallationToken returns a GitHub installation token for the given
// installation, scoped to the specified repositories and permissions.
// Results are cached until 5 minutes before expiry.
func (p *AppTokenProvider) GetInstallationToken(ctx context.Context, installationID int64, repos []string, permissions map[string]string) (string, error) {
	p.mu.Lock()
	if ct, ok := p.cache[installationID]; ok && time.Now().Before(ct.expiresAt.Add(-5*time.Minute)) {
		p.mu.Unlock()
		return ct.token, nil
	}
	p.mu.Unlock()

	// Generate JWT.
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    fmt.Sprintf("%d", p.appID),
		IssuedAt:  jwt.NewNumericDate(now.Add(-60 * time.Second)),
		ExpiresAt: jwt.NewNumericDate(now.Add(10 * time.Minute)),
	}
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := jwtToken.SignedString(p.key)
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	// Request installation token.
	url := fmt.Sprintf("%s/app/installations/%d/access_tokens", p.baseURL, installationID)

	body := map[string]interface{}{
		"repositories": repos,
		"permissions":  permissions,
	}
	bodyJSON, _ := json.Marshal(body)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(bodyJSON))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+signed)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting installation token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("installation token request failed (%d): %s", resp.StatusCode, respBody)
	}

	var result struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding response: %w", err)
	}

	// Cache.
	p.mu.Lock()
	p.cache[installationID] = cachedToken{token: result.Token, expiresAt: result.ExpiresAt}
	p.mu.Unlock()

	return result.Token, nil
}
```

Note: Add `"bytes"` and `"io"` to the import block.

**Step 4: Run tests**

Run: `go test ./internal/github/ -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/github/app.go internal/github/app_test.go
git commit -m "feat: add AppTokenProvider for GitHub App installation tokens"
```

---

### Task 8: Wire AppTokenProvider into Proxy Resolution

**Files:**
- Modify: `internal/proxy/resolver.go`
- Modify: `internal/proxy/proxy.go`

**Step 1: Update ProxyTokenResolver to handle agent tokens**

In `internal/proxy/resolver.go`, add the `AppTokenProvider` as a dependency:

```go
type ProxyTokenResolver struct {
	tokenService     *token.Service
	store            database.Store
	encryptor        *crypto.Encryptor
	appTokenProvider AppTokenProvider // interface or pointer, nil if not configured
}

// AppTokenProvider generates installation tokens for agent (gha_) tokens.
type AppTokenProvider interface {
	GetInstallationToken(ctx context.Context, installationID int64, repos []string, permissions map[string]string) (string, error)
}

func NewProxyTokenResolver(ts *token.Service, store database.Store, enc *crypto.Encryptor, atp AppTokenProvider) *ProxyTokenResolver {
	return &ProxyTokenResolver{tokenService: ts, store: store, encryptor: enc, appTokenProvider: atp}
}
```

Update `ResolveToGitHubToken` to branch on token type:

```go
func (r *ProxyTokenResolver) ResolveToGitHubToken(ctx context.Context, clientToken string) (string, error) {
	pt, err := r.tokenService.Resolve(ctx, clientToken)
	if err != nil {
		return "", fmt.Errorf("resolving token: %w", err)
	}
	if pt == nil {
		return "", fmt.Errorf("invalid token")
	}

	switch token.TokenType(pt.TokenType) {
	case token.TokenTypeProxy:
		return r.resolveProxyToken(ctx, pt)
	case token.TokenTypeAgent:
		return r.resolveAgentToken(ctx, pt)
	default:
		return "", fmt.Errorf("unknown token type %q", pt.TokenType)
	}
}

func (r *ProxyTokenResolver) resolveProxyToken(ctx context.Context, pt *database.ProxyToken) (string, error) {
	if pt.GitHubTokenID == nil {
		return "", fmt.Errorf("proxy token has no linked GitHub credential")
	}
	gt, err := r.store.GetGitHubTokenByID(ctx, *pt.GitHubTokenID)
	if err != nil {
		return "", fmt.Errorf("loading github token: %w", err)
	}
	if gt == nil {
		return "", fmt.Errorf("github token not found")
	}
	plaintext, err := r.encryptor.Decrypt(gt.AccessToken)
	if err != nil {
		return "", fmt.Errorf("decrypting github token: %w", err)
	}
	return plaintext, nil
}

func (r *ProxyTokenResolver) resolveAgentToken(ctx context.Context, pt *database.ProxyToken) (string, error) {
	if r.appTokenProvider == nil {
		return "", fmt.Errorf("agent tokens require GitHub App configuration")
	}
	if pt.InstallationID == nil {
		return "", fmt.Errorf("agent token missing installation_id")
	}

	var repos []string
	if err := json.Unmarshal(pt.Repositories, &repos); err != nil {
		return "", fmt.Errorf("parsing repositories: %w", err)
	}

	scopes, err := database.ParseScopes(pt.Scopes)
	if err != nil {
		return "", fmt.Errorf("parsing scopes: %w", err)
	}

	return r.appTokenProvider.GetInstallationToken(ctx, *pt.InstallationID, repos, scopes)
}
```

**Step 2: Update `NewProxyTokenResolver` call sites**

Find all places `NewProxyTokenResolver` is called and add the `AppTokenProvider` parameter. If no App credentials are configured, pass `nil`.

In the server wiring (likely in `cmd/ghp/main.go` or `internal/server/server.go`), construct the `AppTokenProvider` from config if `cfg.GitHub.AppID != 0 && cfg.GitHub.PrivateKeyFile != ""`.

**Step 3: Similarly update `proxy.Handler.getGitHubToken`**

The `proxy.Handler` also resolves tokens directly (not via `ProxyTokenResolver`). It needs the same branching. Either:
- Refactor to use `ProxyTokenResolver` internally, OR
- Add `AppTokenProvider` to `Handler` and branch in `getGitHubToken`

Prefer adding to `Handler`:

```go
type Handler struct {
	cfg              *config.Config
	tokenService     *token.Service
	store            database.Store
	encryptor        *crypto.Encryptor
	appTokenProvider AppTokenProvider // may be nil
	logger           *slog.Logger
	client           *http.Client
}
```

In `getGitHubToken`:

```go
func (h *Handler) getGitHubToken(r *http.Request, pt *database.ProxyToken) (string, error) {
	switch token.TokenType(pt.TokenType) {
	case token.TokenTypeAgent:
		if h.appTokenProvider == nil {
			return "", fmt.Errorf("agent tokens require GitHub App configuration")
		}
		// ... same as resolveAgentToken above
	default:
		// Proxy token — existing OAuth flow
		if pt.GitHubTokenID == nil {
			return "", fmt.Errorf("token has no linked GitHub credential")
		}
		gt, err := h.store.GetGitHubTokenByID(r.Context(), *pt.GitHubTokenID)
		// ... existing code
	}
}
```

**Step 4: Update tests**

In `internal/proxy/resolver_test.go`:
- Update `NewProxyTokenResolver` calls to pass `nil` as the 4th argument
- Add a test for agent token resolution using a mock `AppTokenProvider`

**Step 5: Run tests**

Run: `go test ./internal/proxy/ -v`
Expected: PASS

**Step 6: Commit**

```bash
git add internal/proxy/resolver.go internal/proxy/proxy.go internal/proxy/resolver_test.go
git commit -m "feat: wire AppTokenProvider into proxy resolution for gha_ tokens"
```

---

### Task 9: CLI Updates

**Files:**
- Modify: `cmd/ghp/token.go`

**Step 1: Update CLI help text and output**

- Line 18: `"Manage ghp proxy tokens"` → `"Manage proxy tokens"`
- Line 24: `"Create a new ghp_ token"` → `"Create a new proxy token"`
- Add `--type` flag to `createCmd` (default `"proxy"`, choices `"proxy"` or `"agent"`)
- Add `--installation-id` flag
- Add `--repos` flag (comma-separated, alternative to `--repo` for multi-repo)
- Update the request body to include `type`, `installation_id`, `repositories` when applicable
- Update the response output to show `type` and `repositories`

**Step 2: Run the full test suite**

Run: `go test ./... -v`
Expected: PASS

**Step 3: Commit**

```bash
git add cmd/ghp/token.go
git commit -m "feat: update CLI token commands for dual token types"
```

---

### Task 10: E2E Test Updates

**Files:**
- Modify: `e2e/tests/tokens.spec.ts:30-32`

**Step 1: Update prefix assertion**

Change line 32:
```typescript
await expect(tokenValue).toContainText("ghx_");
```

Update the comment on line 30:
```typescript
// The token value should start with ghx_.
```

**Step 2: Commit**

```bash
git add e2e/tests/tokens.spec.ts
git commit -m "test: update e2e token prefix assertion from ghp_ to ghx_"
```

---

### Task 11: Documentation Updates

**Files:**
- Modify: `docs/how-it-works.md`
- Modify: `docs/getting-started.md`
- Modify: `docs/web-ui.md`
- Modify: `docs/index.md`
- Modify: `docs/cli/token.md`
- Modify: `README.md`

**Step 1: Find and replace `ghp_` references in docs**

Search all docs for `ghp_` and update:
- `ghp_` token references → `ghx_` (for proxy token examples)
- Add sections explaining the two token types where appropriate
- Update any architecture diagrams or flow descriptions

**Step 2: Commit**

```bash
git add docs/ README.md
git commit -m "docs: update token prefix references from ghp_ to ghx_/gha_"
```

---

### Task 12: Full Integration Test

**Step 1: Run full test suite**

Run: `go test ./... -v -count=1`
Expected: ALL PASS

**Step 2: Run linter if configured**

Run: `golangci-lint run ./...` (if available)

**Step 3: Build**

Run: `go build ./cmd/ghp/`
Expected: Clean build, no errors

**Step 4: Final commit if any fixups needed**

Only if tests/lint revealed issues that needed fixing.
