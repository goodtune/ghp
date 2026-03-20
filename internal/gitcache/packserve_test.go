package gitcache

import (
	"bytes"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
)

func TestServeFetchLocal_EmptyWants(t *testing.T) {
	store := memory.NewStorage()

	var buf bytes.Buffer
	err := ServeFetchLocal(&buf, store, nil, nil)
	if err != nil {
		t.Fatalf("ServeFetchLocal with empty wants: %v", err)
	}

	// Should produce a minimal response (flush packet).
	if buf.Len() == 0 {
		t.Error("expected non-empty response even for empty wants")
	}
}

func TestServeFetchLocal_WithBlob(t *testing.T) {
	store := memory.NewStorage()

	// Store a blob.
	blob := &plumbing.MemoryObject{}
	blob.SetType(plumbing.BlobObject)
	blob.SetSize(11)
	w, _ := blob.Writer()
	w.Write([]byte("hello world"))
	w.Close()
	hash, err := store.SetEncodedObject(blob)
	if err != nil {
		t.Fatalf("SetEncodedObject: %v", err)
	}

	// Serve a fetch for just this blob.
	var buf bytes.Buffer
	err = ServeFetchLocal(&buf, store, []plumbing.Hash{hash}, nil)
	if err != nil {
		t.Fatalf("ServeFetchLocal: %v", err)
	}

	// The response should be non-trivial (contains packfile data).
	if buf.Len() < 20 {
		t.Errorf("response too small (%d bytes), expected packfile data", buf.Len())
	}
}

func TestResolveWantHashes(t *testing.T) {
	store := memory.NewStorage()
	hash1 := plumbing.NewHash("abc123def456abc123def456abc123def456abc1")

	// Store a reference.
	ref := plumbing.NewHashReference("refs/heads/main", hash1)
	if err := store.SetReference(ref); err != nil {
		t.Fatalf("SetReference: %v", err)
	}

	hash2 := plumbing.NewHash("def456abc123def456abc123def456abc123def4")
	result, err := ResolveWantHashes(store, store, []plumbing.Hash{hash2}, []string{"refs/heads/main"})
	if err != nil {
		t.Fatalf("ResolveWantHashes: %v", err)
	}

	if len(result) != 2 {
		t.Fatalf("expected 2 hashes, got %d", len(result))
	}
	if result[0] != hash2 {
		t.Errorf("result[0]: got %s, want %s", result[0], hash2)
	}
	if result[1] != hash1 {
		t.Errorf("result[1]: got %s, want %s (resolved from refs/heads/main)", result[1], hash1)
	}
}

func TestResolveWantHashes_MissingRef(t *testing.T) {
	store := memory.NewStorage()

	_, err := ResolveWantHashes(store, store, nil, []string{"refs/heads/nonexistent"})
	if err == nil {
		t.Fatal("expected error for missing ref")
	}
}
