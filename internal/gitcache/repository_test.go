package gitcache

import (
	"net/url"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
)

func TestOpenManagedRepository_InitialisesNewRepo(t *testing.T) {
	store := memory.NewStorage()
	upstream, _ := url.Parse("https://github.com/test/repo.git")

	m, err := openManagedRepository("test", "repo", upstream, store)
	if err != nil {
		t.Fatalf("openManagedRepository: %v", err)
	}

	if m.owner != "test" {
		t.Errorf("owner: got %q, want %q", m.owner, "test")
	}
	if m.name != "repo" {
		t.Errorf("name: got %q, want %q", m.name, "repo")
	}

	// Should have an "origin" remote.
	remote, err := m.repo.Remote("origin")
	if err != nil {
		t.Fatalf("remote origin not found: %v", err)
	}
	urls := remote.Config().URLs
	if len(urls) == 0 || urls[0] != "https://github.com/test/repo.git" {
		t.Errorf("remote URL: got %v", urls)
	}
}

func TestOpenManagedRepository_ReopensExisting(t *testing.T) {
	store := memory.NewStorage()
	upstream, _ := url.Parse("https://github.com/test/repo.git")

	m1, err := openManagedRepository("test", "repo", upstream, store)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}

	// Open again with the same store — should succeed without re-init.
	m2, err := openManagedRepository("test", "repo", upstream, store)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}

	// Both should reference the same storer.
	if m1.store != m2.store {
		t.Error("second open should reuse the same store")
	}
}

func TestHasAllWants_EmptyRepo(t *testing.T) {
	store := memory.NewStorage()
	upstream, _ := url.Parse("https://github.com/test/repo.git")

	m, err := openManagedRepository("test", "repo", upstream, store)
	if err != nil {
		t.Fatalf("openManagedRepository: %v", err)
	}

	// Asking for any hash in an empty repo should return false.
	has, err := m.HasAllWants(
		[]plumbing.Hash{plumbing.NewHash("abc123def456abc123def456abc123def456abc1")},
		nil,
	)
	if err != nil {
		t.Fatalf("HasAllWants: %v", err)
	}
	if has {
		t.Error("expected false for non-existent hash")
	}

	// Empty wants should return true.
	has, err = m.HasAllWants(nil, nil)
	if err != nil {
		t.Fatalf("HasAllWants empty: %v", err)
	}
	if !has {
		t.Error("expected true for empty wants")
	}
}

func TestHasAllWants_WithObjects(t *testing.T) {
	store := memory.NewStorage()
	upstream, _ := url.Parse("https://github.com/test/repo.git")

	m, err := openManagedRepository("test", "repo", upstream, store)
	if err != nil {
		t.Fatalf("openManagedRepository: %v", err)
	}

	// Manually store a blob object.
	blob := &plumbing.MemoryObject{}
	blob.SetType(plumbing.BlobObject)
	blob.SetSize(5)
	w, _ := blob.Writer()
	w.Write([]byte("hello"))
	w.Close()

	hash, err := store.SetEncodedObject(blob)
	if err != nil {
		t.Fatalf("SetEncodedObject: %v", err)
	}

	// Should find the stored object.
	has, err := m.HasAllWants([]plumbing.Hash{hash}, nil)
	if err != nil {
		t.Fatalf("HasAllWants: %v", err)
	}
	if !has {
		t.Error("expected true for stored object")
	}

	// Should return false when one hash is missing.
	has, err = m.HasAllWants(
		[]plumbing.Hash{hash, plumbing.NewHash("0000000000000000000000000000000000000000")},
		nil,
	)
	if err != nil {
		t.Fatalf("HasAllWants: %v", err)
	}
	if has {
		t.Error("expected false when one hash is missing")
	}
}

func TestHasAnyUpdate(t *testing.T) {
	store := memory.NewStorage()
	upstream, _ := url.Parse("https://github.com/test/repo.git")

	m, err := openManagedRepository("test", "repo", upstream, store)
	if err != nil {
		t.Fatalf("openManagedRepository: %v", err)
	}

	hash1 := plumbing.NewHash("abc123def456abc123def456abc123def456abc1")

	// Store a reference.
	ref := plumbing.NewHashReference("refs/heads/main", hash1)
	if err := store.SetReference(ref); err != nil {
		t.Fatalf("SetReference: %v", err)
	}

	// Same hash — no update.
	hasUpdate, err := m.HasAnyUpdate(map[string]plumbing.Hash{
		"refs/heads/main": hash1,
	})
	if err != nil {
		t.Fatalf("HasAnyUpdate: %v", err)
	}
	if hasUpdate {
		t.Error("expected no update when hashes match")
	}

	// Different hash — has update.
	hash2 := plumbing.NewHash("def456abc123def456abc123def456abc123def4")
	hasUpdate, err = m.HasAnyUpdate(map[string]plumbing.Hash{
		"refs/heads/main": hash2,
	})
	if err != nil {
		t.Fatalf("HasAnyUpdate: %v", err)
	}
	if !hasUpdate {
		t.Error("expected update when hashes differ")
	}

	// New ref — has update.
	hasUpdate, err = m.HasAnyUpdate(map[string]plumbing.Hash{
		"refs/heads/feature": hash1,
	})
	if err != nil {
		t.Fatalf("HasAnyUpdate: %v", err)
	}
	if !hasUpdate {
		t.Error("expected update for new ref")
	}
}

// Ensure the unused import doesn't cause issues — object is used
// indirectly via go-git's type system.
var _ = (*object.Blob)(nil)
