package gitcache

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/storage"
	"github.com/go-git/go-git/v5/storage/filesystem"
)

// ValidNameRe matches valid GitHub owner and repository names: alphanumeric,
// hyphens, underscores, and dots. Rejects path separators, "..", and other
// characters that could escape the cache root directory.
var ValidNameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// FilesystemStorageFactory stores cached bare repos on local disk under a
// root directory. Each repository gets its own subdirectory at
// <root>/<owner>/<repo>.
type FilesystemStorageFactory struct {
	root string
}

// NewFilesystemStorageFactory creates a factory that stores bare repos
// under root. The root directory is created if it does not exist.
func NewFilesystemStorageFactory(root string) (*FilesystemStorageFactory, error) {
	if err := os.MkdirAll(root, 0750); err != nil {
		return nil, fmt.Errorf("create cache root %s: %w", root, err)
	}
	return &FilesystemStorageFactory{root: root}, nil
}

func (f *FilesystemStorageFactory) repoPath(owner, repo string) (string, error) {
	if !ValidNameRe.MatchString(owner) || owner == "." || owner == ".." {
		return "", fmt.Errorf("invalid owner name: %q", owner)
	}
	if !ValidNameRe.MatchString(repo) || repo == "." || repo == ".." {
		return "", fmt.Errorf("invalid repo name: %q", repo)
	}
	return filepath.Join(f.root, owner, repo), nil
}

// Open returns a filesystem-backed go-git Storer for the given repository.
// The directory is created if it does not exist.
func (f *FilesystemStorageFactory) Open(owner, repo string) (storage.Storer, error) {
	p, err := f.repoPath(owner, repo)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(p, 0750); err != nil {
		return nil, fmt.Errorf("create repo cache dir %s: %w", p, err)
	}
	fs := osfs.New(p)
	return filesystem.NewStorage(fs, cache.NewObjectLRUDefault()), nil
}

// Delete removes all cached data for a repository from disk.
func (f *FilesystemStorageFactory) Delete(owner, repo string) error {
	p, err := f.repoPath(owner, repo)
	if err != nil {
		return err
	}
	if err := os.RemoveAll(p); err != nil {
		return fmt.Errorf("delete cache dir %s: %w", p, err)
	}
	// Clean up empty owner directory.
	ownerDir := filepath.Dir(p)
	entries, err := os.ReadDir(ownerDir)
	if err == nil && len(entries) == 0 {
		os.Remove(ownerDir) // best-effort
	}
	return nil
}
