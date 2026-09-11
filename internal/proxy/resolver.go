package proxy

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/token"
)

const credentialCacheTTL = 5 * time.Minute

type cachedCredential struct {
	plaintext string
	cachedAt  time.Time
}

// AppTokenProvider generates installation tokens for agent (gha_) tokens.
type AppTokenProvider interface {
	GetInstallationToken(ctx context.Context, installationID int64, repos []string, permissions map[string]string) (string, error)
}

// MultiAppTokenProvider generates installation tokens with app-specific dispatch.
type MultiAppTokenProvider interface {
	AppTokenProvider
	// GetInstallationTokenForApp returns a token using the provider for the specified app.
	// If appID is empty, the default provider is used.
	GetInstallationTokenForApp(ctx context.Context, appID string, installationID int64, repos []string, permissions map[string]string) (string, error)
}

// ProxyTokenResolver resolves client tokens (ghx_/gha_) to real GitHub access tokens.
type ProxyTokenResolver struct {
	tokenService     *token.Service
	store            database.Store
	encryptor        *crypto.Encryptor
	appTokenProvider AppTokenProvider // nil if not configured

	// credCache caches decrypted GitHub access tokens keyed by github_token_id
	// to avoid a database read + decrypt on every proxied request.
	credCache sync.Map // map[string]cachedCredential
}

// NewProxyTokenResolver creates a new resolver.
func NewProxyTokenResolver(ts *token.Service, store database.Store, enc *crypto.Encryptor, atp AppTokenProvider) *ProxyTokenResolver {
	return &ProxyTokenResolver{tokenService: ts, store: store, encryptor: enc, appTokenProvider: atp}
}

// ResolveToGitHubToken resolves a client token to a plaintext GitHub access token.
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

	// Check the credential cache first.
	if entry, ok := r.credCache.Load(*pt.GitHubTokenID); ok {
		cc := entry.(cachedCredential)
		if time.Since(cc.cachedAt) < credentialCacheTTL {
			return cc.plaintext, nil
		}
		r.credCache.Delete(*pt.GitHubTokenID)
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

	// Cache the decrypted credential.
	r.credCache.Store(*pt.GitHubTokenID, cachedCredential{
		plaintext: plaintext,
		cachedAt:  time.Now(),
	})

	return plaintext, nil
}

// ResolveProxyTokenToGitHub resolves a ProxyToken database record to the
// underlying plaintext GitHub credential. This is used for cache warming
// where the caller already has the database record and does not need the
// full Resolve-from-plaintext-token flow.
func (r *ProxyTokenResolver) ResolveProxyTokenToGitHub(ctx context.Context, pt *database.ProxyToken) (string, error) {
	switch token.TokenType(pt.TokenType) {
	case token.TokenTypeProxy:
		return r.resolveProxyToken(ctx, pt)
	case token.TokenTypeAgent:
		return r.resolveAgentToken(ctx, pt)
	default:
		return "", fmt.Errorf("unknown token type %q", pt.TokenType)
	}
}

func (r *ProxyTokenResolver) resolveAgentToken(ctx context.Context, pt *database.ProxyToken) (string, error) {
	if r.appTokenProvider == nil {
		return "", fmt.Errorf("agent tokens require GitHub App configuration")
	}
	if pt.InstallationID == nil {
		return "", fmt.Errorf("agent token missing installation_id")
	}

	si, err := parseScopeInfo(pt)
	if err != nil {
		return "", fmt.Errorf("parsing agent token scope: %w", err)
	}

	// If the provider supports multi-app dispatch and the token has an app_id, use it.
	if multi, ok := r.appTokenProvider.(MultiAppTokenProvider); ok && pt.AppID != nil {
		return multi.GetInstallationTokenForApp(ctx, *pt.AppID, *pt.InstallationID, si.Repos, si.Scopes)
	}

	return r.appTokenProvider.GetInstallationToken(ctx, *pt.InstallationID, si.Repos, si.Scopes)
}
