package proxy

import (
	"context"
	"fmt"

	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/token"
)

// ProxyTokenResolver resolves ghp_ tokens to real GitHub access tokens.
type ProxyTokenResolver struct {
	tokenService *token.Service
	store        database.Store
	encryptor    *crypto.Encryptor
}

// NewProxyTokenResolver creates a new resolver.
func NewProxyTokenResolver(ts *token.Service, store database.Store, enc *crypto.Encryptor) *ProxyTokenResolver {
	return &ProxyTokenResolver{tokenService: ts, store: store, encryptor: enc}
}

// ResolveToGitHubToken resolves a ghp_ token to a plaintext GitHub access token.
func (r *ProxyTokenResolver) ResolveToGitHubToken(ctx context.Context, ghpToken string) (string, error) {
	pt, err := r.tokenService.Resolve(ctx, ghpToken)
	if err != nil {
		return "", fmt.Errorf("resolving token: %w", err)
	}
	if pt == nil {
		return "", fmt.Errorf("invalid token")
	}

	gt, err := r.store.GetGitHubTokenByID(ctx, pt.GitHubTokenID)
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
