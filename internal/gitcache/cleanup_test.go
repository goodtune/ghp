package gitcache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/goodtune/ghp/internal/database"
)

func TestEnforceRepoSizeLimit_NoLimit(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "aaa", 100)
	writeFile(t, dir, "bbb", 200)

	repo := &database.CachedRepository{Owner: "o", Name: "r"}
	evicted := enforceRepoSizeLimit(dir, repo)
	if evicted != 0 {
		t.Errorf("expected 0 evicted with no limit, got %d", evicted)
	}
	assertFileCount(t, dir, 2)
}

func TestEnforceRepoSizeLimit_UnderLimit(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "aaa", 100)
	writeFile(t, dir, "bbb", 200)

	limit := 1 // 1 MB — 300 bytes is well under
	repo := &database.CachedRepository{Owner: "o", Name: "r", MaxCacheSizeMB: &limit}
	evicted := enforceRepoSizeLimit(dir, repo)
	if evicted != 0 {
		t.Errorf("expected 0 evicted when under limit, got %d", evicted)
	}
	assertFileCount(t, dir, 2)
}

func TestEnforceRepoSizeLimit_EvictsOldest(t *testing.T) {
	dir := t.TempDir()

	// Create files and assign explicit, distinct mtimes to avoid
	// flakiness on filesystems with coarse timestamp resolution.
	oldest := writeFile(t, dir, "oldest", 600*1024) // 600 KB
	middle := writeFile(t, dir, "middle", 400*1024)  // 400 KB
	newest := writeFile(t, dir, "newest", 300*1024)  // 300 KB

	base := time.Now().Add(-2 * time.Minute)
	setChtimes(t, oldest, base)
	setChtimes(t, middle, base.Add(1*time.Minute))
	setChtimes(t, newest, base.Add(2*time.Minute))

	// Total: 1300 KB. Limit: 1 MB (1024 KB). Need to evict ~276 KB → oldest file (600 KB).
	limit := 1
	repo := &database.CachedRepository{Owner: "o", Name: "r", MaxCacheSizeMB: &limit}
	evicted := enforceRepoSizeLimit(dir, repo)
	if evicted != 1 {
		t.Errorf("expected 1 evicted, got %d", evicted)
	}

	// Oldest should be gone, others remain.
	if _, err := os.Stat(oldest); !os.IsNotExist(err) {
		t.Error("expected oldest file to be deleted")
	}
	assertFileCount(t, dir, 2)
}

func TestEnforceRepoSizeLimit_EvictsMultiple(t *testing.T) {
	dir := t.TempDir()

	// Create 5 files of 300 KB each = 1500 KB total.
	for i, name := range []string{"a", "b", "c", "d", "e"} {
		writeFile(t, dir, name, 300*1024)
		// Ensure distinct mtimes.
		past := time.Now().Add(-time.Duration(5-i) * time.Minute)
		setChtimes(t, filepath.Join(dir, name), past)
	}

	// Limit: 1 MB (1024 KB). Need to evict at least 476 KB → 2 files (600 KB).
	limit := 1
	repo := &database.CachedRepository{Owner: "o", Name: "r", MaxCacheSizeMB: &limit}
	evicted := enforceRepoSizeLimit(dir, repo)
	if evicted != 2 {
		t.Errorf("expected 2 evicted, got %d", evicted)
	}
	assertFileCount(t, dir, 3)
}

func TestEnforceRepoSizeLimit_SkipsTmpFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, ".tmp-abc123", 500*1024)
	writeFile(t, dir, "real", 500*1024)

	// Only "real" counts toward size (500 KB < 1 MB limit).
	limit := 1
	repo := &database.CachedRepository{Owner: "o", Name: "r", MaxCacheSizeMB: &limit}
	evicted := enforceRepoSizeLimit(dir, repo)
	if evicted != 0 {
		t.Errorf("expected 0 evicted, got %d", evicted)
	}
	assertFileCount(t, dir, 2)
}

func TestEnforceRepoSizeLimit_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	limit := 1
	repo := &database.CachedRepository{Owner: "o", Name: "r", MaxCacheSizeMB: &limit}
	evicted := enforceRepoSizeLimit(dir, repo)
	if evicted != 0 {
		t.Errorf("expected 0 evicted for empty dir, got %d", evicted)
	}
}

func TestEnforceRepoSizeLimit_NonexistentDir(t *testing.T) {
	limit := 1
	repo := &database.CachedRepository{Owner: "o", Name: "r", MaxCacheSizeMB: &limit}
	evicted := enforceRepoSizeLimit("/nonexistent/path", repo)
	if evicted != 0 {
		t.Errorf("expected 0 evicted for nonexistent dir, got %d", evicted)
	}
}

func TestScanCacheDir(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "file1", 100)
	writeFile(t, dir, "file2", 200)
	writeFile(t, dir, ".tmp-partial", 50) // should be skipped

	files, total := scanCacheDir(dir)
	if len(files) != 2 {
		t.Errorf("expected 2 files, got %d", len(files))
	}
	if total != 300 {
		t.Errorf("expected total 300, got %d", total)
	}
}

// writeFile creates a file with the given size and returns its path.
func writeFile(t *testing.T, dir, name string, size int) string {
	t.Helper()
	path := filepath.Join(dir, name)
	data := make([]byte, size)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func setChtimes(t *testing.T, path string, mtime time.Time) {
	t.Helper()
	if err := os.Chtimes(path, mtime, mtime); err != nil {
		t.Fatalf("failed to set mtime for %s: %v", filepath.Base(path), err)
	}
}

func assertFileCount(t *testing.T, dir string, expected int) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() {
			count++
		}
	}
	if count != expected {
		t.Errorf("expected %d files, got %d", expected, count)
	}
}
