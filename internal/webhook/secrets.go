package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/goodtune/ghp/internal/crypto"
	"github.com/goodtune/ghp/internal/database"
)

// Candidate is one secret the ingress handler may verify a delivery against,
// together with the app it belongs to ("" for the global fallback secret).
type Candidate struct {
	AppRecordID string
	GitHubAppID int64
	AppName     string
	Secret      []byte
}

// SecretSource yields the ordered list of candidate secrets for a delivery.
// The handler tries each in turn and accepts the first that verifies.
type SecretSource interface {
	Candidates(ctx context.Context, targetType string, targetID string) ([]Candidate, error)
}

// defaultSecretCacheTTL bounds how stale the resolver's view of app secrets
// can be. Admin API mutations call Invalidate so the common path is fresh;
// the TTL covers other instances in HA deployments and direct DB edits.
const defaultSecretCacheTTL = 30 * time.Second

// StoreSecretSource resolves candidate secrets from the app store, decrypting
// each app's webhook secret with the configured encryptor. Results are cached
// for a short TTL.
type StoreSecretSource struct {
	store  database.Store
	enc    *crypto.Encryptor
	global []byte
	logger *slog.Logger
	ttl    time.Duration

	mu        sync.Mutex
	cached    []appSecret
	fetchedAt time.Time
}

type appSecret struct {
	recordID string
	appID    int64
	name     string
	secret   []byte
}

// NewStoreSecretSource creates a resolver over store. globalSecret is the
// optional webhooks.secret fallback; pass "" to disable it.
func NewStoreSecretSource(store database.Store, enc *crypto.Encryptor, globalSecret string, logger *slog.Logger) *StoreSecretSource {
	var global []byte
	if globalSecret != "" {
		global = []byte(globalSecret)
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &StoreSecretSource{store: store, enc: enc, global: global, logger: logger, ttl: defaultSecretCacheTTL}
}

// Invalidate drops the cached app secrets so the next lookup re-reads the
// store. Call it after an app is created, updated, or deleted.
func (s *StoreSecretSource) Invalidate() {
	s.mu.Lock()
	s.cached = nil
	s.fetchedAt = time.Time{}
	s.mu.Unlock()
}

// Candidates implements SecretSource. Order:
//
//  1. the app whose GitHub App ID equals targetID, when targetType is
//     "integration" and that app has a secret;
//  2. the global fallback secret, when configured;
//  3. for non-integration targets only (repository, organization, ...
//     hooks that an operator may have configured with an app's secret),
//     every other app that has a secret.
//
// An integration delivery is never tried against other apps' secrets: a
// delivery addressed to app A must not verify under app B's secret. The
// global secret is always a candidate (after the matched app) so operators
// who share one secret across apps and repository hooks can keep doing so; a
// delivery that verifies only under the global secret is stored without an
// app attribution.
func (s *StoreSecretSource) Candidates(ctx context.Context, targetType, targetID string) ([]Candidate, error) {
	apps, err := s.apps(ctx)
	if err != nil {
		return nil, err
	}

	var out []Candidate
	if targetType == TargetTypeIntegration {
		id, perr := strconv.ParseInt(targetID, 10, 64)
		if perr == nil {
			for _, a := range apps {
				if a.appID == id && len(a.secret) > 0 {
					out = append(out, Candidate{AppRecordID: a.recordID, GitHubAppID: a.appID, AppName: a.name, Secret: a.secret})
					break
				}
			}
		}
		if len(s.global) > 0 {
			out = append(out, Candidate{Secret: s.global})
		}
		return out, nil
	}

	if len(s.global) > 0 {
		out = append(out, Candidate{Secret: s.global})
	}
	for _, a := range apps {
		if len(a.secret) > 0 {
			out = append(out, Candidate{AppRecordID: a.recordID, GitHubAppID: a.appID, AppName: a.name, Secret: a.secret})
		}
	}
	return out, nil
}

func (s *StoreSecretSource) apps(ctx context.Context) ([]appSecret, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cached != nil && time.Since(s.fetchedAt) < s.ttl {
		return s.cached, nil
	}
	list, err := s.store.ListApps(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing apps for webhook secrets: %w", err)
	}
	out := make([]appSecret, 0, len(list))
	for _, a := range list {
		entry := appSecret{recordID: a.ID, appID: a.AppID, name: a.Name}
		if a.WebhookSecret != "" {
			plain := a.WebhookSecret
			if s.enc != nil {
				plain, err = s.enc.Decrypt(a.WebhookSecret)
				if err != nil {
					// Log and skip rather than fail every delivery: one
					// corrupt record must not take the ingress down.
					s.logger.Error("webhook_secret_decrypt_failed", "app_record_id", a.ID, "error", err)
					out = append(out, entry)
					continue
				}
			}
			entry.secret = []byte(plain)
		}
		out = append(out, entry)
	}
	s.cached = out
	s.fetchedAt = time.Now()
	return out, nil
}

// StaticSecretSource is a SecretSource backed by a fixed candidate list,
// used by tests.
type StaticSecretSource []Candidate

// Candidates returns the static list regardless of target.
func (s StaticSecretSource) Candidates(context.Context, string, string) ([]Candidate, error) {
	return []Candidate(s), nil
}
