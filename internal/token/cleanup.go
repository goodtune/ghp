package token

import (
	"context"
	"log/slog"
	"time"

	"github.com/goodtune/ghp/internal/config"
	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/metrics"
)

const cleanupInterval = time.Hour

// StartCleanup launches a background goroutine that periodically hard-deletes
// proxy tokens that have been expired or revoked for longer than the retention
// period configured in cfg.  The retention period is re-read from cfg on every
// cleanup cycle so that a SIGUSR1 hot-reload takes effect without a restart.
// The goroutine stops when ctx is cancelled.  When the configured period is
// zero or negative the cleanup is disabled and this function returns immediately.
func StartCleanup(ctx context.Context, store database.Store, cfg *config.Config) {
	retentionPeriod := cfg.Tokens.ExpiredTokenRetentionPeriod
	if retentionPeriod <= 0 {
		if retentionPeriod < 0 {
			slog.Warn("token cleanup: negative retention period is invalid; cleanup disabled",
				"expired_token_retention_period", retentionPeriod)
		} else {
			slog.Info("token cleanup: disabled (expired_token_retention_period = 0)")
		}
		return
	}
	go runCleanupLoop(ctx, store, cfg)
}

func runCleanupLoop(ctx context.Context, store database.Store, cfg *config.Config) {
	// Run once immediately so stale tokens are removed promptly after startup.
	runCleanupCycle(ctx, store, cfg.Tokens.ExpiredTokenRetentionPeriod)

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Re-read retention period each cycle so SIGUSR1 hot-reloads apply
			// without a restart.
			runCleanupCycle(ctx, store, cfg.Tokens.ExpiredTokenRetentionPeriod)
		}
	}
}

func runCleanupCycle(ctx context.Context, store database.Store, retentionPeriod time.Duration) {
	n, err := store.DeleteExpiredProxyTokens(ctx, retentionPeriod)
	// Record partial progress first: DeleteExpiredProxyTokens can return a
	// non-zero count alongside an error (e.g., Vault deleted some tokens and
	// then failed), so observability should reflect the successful deletions
	// regardless of the error outcome.
	if n > 0 {
		metrics.TokenCleanupDeletedTotal.Add(float64(n))
		slog.Info("token cleanup: deleted expired/revoked tokens", "count", n)
	}
	if err != nil {
		// Suppress noisy shutdown logs: when the lifecycle context is being
		// cancelled, a cancellation error from the store is expected and not
		// actionable.
		if ctx.Err() != nil {
			return
		}
		slog.Error("token cleanup: failed to delete expired/revoked tokens", "err", err)
	}
}
