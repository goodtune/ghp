package token

import (
	"context"
	"log/slog"
	"time"

	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/metrics"
)

const cleanupInterval = time.Hour

// StartCleanup launches a background goroutine that periodically hard-deletes
// proxy tokens that have been expired or revoked for longer than retentionPeriod.
// The goroutine stops when ctx is cancelled.  When retentionPeriod is zero or
// negative the cleanup is disabled and this function returns immediately.
func StartCleanup(ctx context.Context, store database.Store, retentionPeriod time.Duration) {
	if retentionPeriod <= 0 {
		if retentionPeriod < 0 {
			slog.Warn("token cleanup: negative retention period is invalid; cleanup disabled",
				"expired_token_retention_period", retentionPeriod)
		} else {
			slog.Info("token cleanup: disabled (expired_token_retention_period = 0)")
		}
		return
	}
	go runCleanupLoop(ctx, store, retentionPeriod)
}

func runCleanupLoop(ctx context.Context, store database.Store, retentionPeriod time.Duration) {
	// Run once immediately so stale tokens are removed promptly after startup.
	runCleanupCycle(ctx, store, retentionPeriod)

	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runCleanupCycle(ctx, store, retentionPeriod)
		}
	}
}

func runCleanupCycle(ctx context.Context, store database.Store, retentionPeriod time.Duration) {
	n, err := store.DeleteExpiredProxyTokens(ctx, retentionPeriod)
	if err != nil {
		slog.Error("token cleanup: failed to delete expired tokens", "err", err)
		return
	}
	if n > 0 {
		metrics.TokenCleanupDeletedTotal.Add(float64(n))
		slog.Info("token cleanup: deleted expired/revoked tokens", "count", n)
	}
}
