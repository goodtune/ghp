package proxy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/token"
)

// AppTokenProvider generates installation tokens for agent (gha_) tokens.
type AppTokenProvider interface {
	GetInstallationToken(ctx context.Context, installationID int64, repos []string, permissions map[string]string) (string, error)
}

// ProxyTokenResolver resolves client tokens (ghx_/gha_) to real GitHub access tokens.
type ProxyTokenResolver struct {
	tokenService     *token.Service
	store            database.Store
	encryptor        *crypto.Encryptor
	appTokenProvider AppTokenProvider // nil if not configured
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
	// Repositories may be null for open-scoped tokens.
	json.Unmarshal(pt.Repositories, &repos)

	var scopes database.Scopes
	// Scopes may be null for open-scoped tokens.
	json.Unmarshal(pt.Scopes, &scopes)

	return r.appTokenProvider.GetInstallationToken(ctx, *pt.InstallationID, repos, scopes)
}
