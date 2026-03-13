package github

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
)

// AppRegistry manages multiple AppTokenProviders, one per configured GitHub App.
type AppRegistry struct {
	mu        sync.RWMutex
	providers map[string]*AppTokenProvider // keyed by App.ID (database UUID)
	defaultID string                       // ID of the default app
	store     database.Store
	encryptor *crypto.Encryptor
	logger    *slog.Logger
}

// NewAppRegistry creates a new registry. Call LoadAll to populate it.
func NewAppRegistry(store database.Store, enc *crypto.Encryptor, logger *slog.Logger) *AppRegistry {
	return &AppRegistry{
		providers: make(map[string]*AppTokenProvider),
		store:     store,
		encryptor: enc,
		logger:    logger,
	}
}

// LoadAll reads all App records from the store and creates an AppTokenProvider
// for each one that has a valid private key.
func (r *AppRegistry) LoadAll(ctx context.Context) error {
	apps, err := r.store.ListApps(ctx)
	if err != nil {
		return fmt.Errorf("listing apps: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, app := range apps {
		if err := r.loadAppLocked(app); err != nil {
			r.logger.Warn("skipping app", "app_id", app.ID, "name", app.Name, "error", err)
			continue
		}
		if app.IsDefault {
			r.defaultID = app.ID
		}
	}
	r.logger.Info("app registry loaded", "count", len(r.providers))
	return nil
}

// loadAppLocked creates a provider for the given app. Caller must hold r.mu.
func (r *AppRegistry) loadAppLocked(app *database.App) error {
	privateKey := app.PrivateKey
	if r.encryptor != nil && privateKey != "" {
		decrypted, err := r.encryptor.Decrypt(privateKey)
		if err != nil {
			// If decryption fails, try using the key as-is (may be plaintext in dev).
			r.logger.Debug("private key decryption failed, using as-is", "app_id", app.ID)
			decrypted = privateKey
		}
		privateKey = decrypted
	}

	if privateKey == "" {
		return fmt.Errorf("no private key configured")
	}

	provider, err := NewAppTokenProvider(AppConfig{
		AppID:      app.AppID,
		PrivateKey: privateKey,
		BaseURL:    app.BaseURL,
	})
	if err != nil {
		return fmt.Errorf("creating provider: %w", err)
	}

	r.providers[app.ID] = provider
	r.logger.Info("app provider loaded", "app_id", app.ID, "name", app.Name, "github_app_id", app.AppID)
	return nil
}

// Get returns the AppTokenProvider for the given app ID.
func (r *AppRegistry) Get(appID string) (*AppTokenProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	provider, ok := r.providers[appID]
	if !ok {
		return nil, fmt.Errorf("no provider for app %s", appID)
	}
	return provider, nil
}

// GetDefault returns the AppTokenProvider for the default app.
func (r *AppRegistry) GetDefault() (*AppTokenProvider, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.defaultID == "" {
		// If no explicit default, return the first provider if there's only one.
		if len(r.providers) == 1 {
			for _, p := range r.providers {
				return p, nil
			}
		}
		return nil, fmt.Errorf("no default app configured")
	}
	provider, ok := r.providers[r.defaultID]
	if !ok {
		return nil, fmt.Errorf("default app provider not found")
	}
	return provider, nil
}

// GetDefaultID returns the database ID of the default app, or empty string if none.
func (r *AppRegistry) GetDefaultID() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.defaultID
}

// Reload re-reads apps from the store and updates providers.
func (r *AppRegistry) Reload(ctx context.Context) error {
	apps, err := r.store.ListApps(ctx)
	if err != nil {
		return fmt.Errorf("listing apps: %w", err)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Track which IDs are still valid.
	seen := make(map[string]bool)
	for _, app := range apps {
		seen[app.ID] = true
		if _, exists := r.providers[app.ID]; !exists {
			if err := r.loadAppLocked(app); err != nil {
				r.logger.Warn("skipping app on reload", "app_id", app.ID, "name", app.Name, "error", err)
			}
		}
		if app.IsDefault {
			r.defaultID = app.ID
		}
	}

	// Remove providers for deleted apps.
	for id := range r.providers {
		if !seen[id] {
			delete(r.providers, id)
		}
	}

	return nil
}

// Count returns the number of loaded providers.
func (r *AppRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.providers)
}

// GetInstallationToken resolves an installation token using the default app provider.
// Satisfies the proxy.AppTokenProvider interface.
func (r *AppRegistry) GetInstallationToken(ctx context.Context, installationID int64, repos []string, permissions map[string]string) (string, error) {
	provider, err := r.GetDefault()
	if err != nil {
		return "", err
	}
	return provider.GetInstallationToken(ctx, installationID, repos, permissions)
}

// GetInstallationTokenForApp resolves an installation token using a specific app's provider.
// If appID is empty, falls back to the default provider.
// Satisfies the proxy.MultiAppTokenProvider interface.
func (r *AppRegistry) GetInstallationTokenForApp(ctx context.Context, appID string, installationID int64, repos []string, permissions map[string]string) (string, error) {
	var provider *AppTokenProvider
	var err error
	if appID != "" {
		provider, err = r.Get(appID)
	} else {
		provider, err = r.GetDefault()
	}
	if err != nil {
		return "", err
	}
	return provider.GetInstallationToken(ctx, installationID, repos, permissions)
}
