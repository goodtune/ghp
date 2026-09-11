package gitcache

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFilesystemStorageFactory_OpenAndDelete(t *testing.T) {
	root := t.TempDir()

	factory, err := NewFilesystemStorageFactory(root)
	if err != nil {
		t.Fatalf("NewFilesystemStorageFactory: %v", err)
	}

	// Open creates the directory and returns a valid storer.
	store, err := factory.Open("myorg", "myrepo")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if store == nil {
		t.Fatal("Open returned nil storer")
	}

	// Verify directory exists.
	repoDir := filepath.Join(root, "myorg", "myrepo")
	info, err := os.Stat(repoDir)
	if err != nil {
		t.Fatalf("repo dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal("repo path is not a directory")
	}

	// Opening again should succeed (idempotent).
	store2, err := factory.Open("myorg", "myrepo")
	if err != nil {
		t.Fatalf("Open again: %v", err)
	}
	if store2 == nil {
		t.Fatal("second Open returned nil storer")
	}

	// Delete removes the directory.
	if err := factory.Delete("myorg", "myrepo"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(repoDir); !os.IsNotExist(err) {
		t.Fatalf("repo dir should be gone after Delete, got err: %v", err)
	}

	// Delete of non-existent repo should not error (RemoveAll on missing path is ok).
	if err := factory.Delete("myorg", "nonexistent"); err != nil {
		t.Fatalf("Delete non-existent: %v", err)
	}
}

func TestFilesystemStorageFactory_CleansEmptyOwnerDir(t *testing.T) {
	root := t.TempDir()

	factory, err := NewFilesystemStorageFactory(root)
	if err != nil {
		t.Fatalf("NewFilesystemStorageFactory: %v", err)
	}

	// Create and delete the only repo under an owner.
	if _, err := factory.Open("solo-owner", "only-repo"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := factory.Delete("solo-owner", "only-repo"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Owner directory should be cleaned up.
	ownerDir := filepath.Join(root, "solo-owner")
	if _, err := os.Stat(ownerDir); !os.IsNotExist(err) {
		t.Fatalf("owner dir should be removed when empty, got err: %v", err)
	}
}
