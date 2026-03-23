package gitcache

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/goodtune/ghp/internal/database"
	"github.com/goodtune/ghp/internal/metrics"
)

// cachedFile holds metadata about a single protocol response cache file.
type cachedFile struct {
	path  string
	size  int64
	mtime time.Time
}

// StartCleanup launches a background goroutine that periodically enforces
// per-repository cache size limits by evicting the oldest protocol response
// files. The goroutine stops when ctx is cancelled.
func StartCleanup(ctx context.Context, responseCacheDir string, store database.Store, interval time.Duration) {
	if interval <= 0 {
		slog.Warn("cache cleanup: non-positive interval; cleanup disabled", "interval", interval)
		return
	}
	go runCleanupLoop(ctx, responseCacheDir, store, interval)
}

func runCleanupLoop(ctx context.Context, responseCacheDir string, store database.Store, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runCleanupCycle(ctx, responseCacheDir, store)
		}
	}
}

func runCleanupCycle(ctx context.Context, responseCacheDir string, store database.Store) {
	repos, err := store.ListCachedRepositories(ctx)
	if err != nil {
		slog.Error("cache cleanup: failed to list repos", "err", err)
		return
	}

	for _, repo := range repos {
		if ctx.Err() != nil {
			return
		}
		repoDir := filepath.Join(responseCacheDir, "_protocol_responses", repo.Owner, repo.Name)
		evicted := enforceRepoSizeLimit(repoDir, repo)
		if evicted > 0 {
			slog.Info("cache cleanup: evicted files",
				"repo", repo.Owner+"/"+repo.Name,
				"evicted", evicted,
			)
		}
	}
}

// enforceRepoSizeLimit scans the protocol response cache directory for a
// repository, reports the total size via metrics, and deletes the oldest
// files if MaxCacheSizeMB is set and the total exceeds the limit. Returns
// the number of files evicted.
func enforceRepoSizeLimit(repoDir string, repo *database.CachedRepository) int {
	files, totalSize := scanCacheDir(repoDir)
	metrics.CacheResponseSizeBytes.WithLabelValues(repo.Owner, repo.Name).Set(float64(totalSize))

	if repo.MaxCacheSizeMB == nil || *repo.MaxCacheSizeMB <= 0 {
		return 0
	}

	limitBytes := int64(*repo.MaxCacheSizeMB) * 1024 * 1024
	if totalSize <= limitBytes {
		return 0
	}

	// Sort by mtime ascending (oldest first) for eviction.
	sort.Slice(files, func(i, j int) bool {
		return files[i].mtime.Before(files[j].mtime)
	})

	evicted := 0
	for _, f := range files {
		if totalSize <= limitBytes {
			break
		}
		if err := os.Remove(f.path); err != nil {
			slog.Warn("cache cleanup: failed to remove file", "path", f.path, "err", err)
			continue
		}
		totalSize -= f.size
		evicted++
		metrics.CacheEvictionTotal.WithLabelValues(repo.Owner, repo.Name).Inc()
	}

	// Update size gauge after eviction.
	metrics.CacheResponseSizeBytes.WithLabelValues(repo.Owner, repo.Name).Set(float64(totalSize))
	return evicted
}

// scanCacheDir reads the contents of a directory and returns file metadata
// and the total size. Dotfiles (e.g. ".tmp-" partial writes) and
// subdirectories are skipped.
func scanCacheDir(dir string) ([]cachedFile, int64) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("cache cleanup: failed to read cache directory", "dir", dir, "err", err)
		}
		return nil, 0
	}

	var files []cachedFile
	var totalSize int64
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Skip temporary files being written by the handler.
		if len(name) > 0 && name[0] == '.' {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, cachedFile{
			path:  filepath.Join(dir, name),
			size:  info.Size(),
			mtime: info.ModTime(),
		})
		totalSize += info.Size()
	}
	return files, totalSize
}
