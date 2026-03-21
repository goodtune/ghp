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
		t.Fatalf("response too small (%d bytes), expected packfile data", buf.Len())
	}

	// Validate the protocol v2 wire format.
	// Expected: "packfile\n" section header + sideband data + flush (0000)
	// Note: NO delimiter before the first section — delimiters only separate
	// sections (e.g. acknowledgments delim-pkt packfile).
	data := buf.Bytes()
	t.Logf("raw response (%d bytes): %x", len(data), data[:min(len(data), 80)])

	// First pkt-line should be the "packfile\n" section header.
	// Format: 4-byte hex length + payload. "packfile\n" = 9 bytes, total 13.
	// Length includes itself: 9 + 4 = 13 = 0x000d
	pktStart := 0
	pktLenStr := string(data[pktStart : pktStart+4])
	t.Logf("packfile section header pkt-line length: %q", pktLenStr)
	// Find end of this pkt-line
	pktLen := 0
	for i, c := range []byte(pktLenStr) {
		v := 0
		if c >= '0' && c <= '9' {
			v = int(c - '0')
		} else if c >= 'a' && c <= 'f' {
			v = int(c-'a') + 10
		}
		pktLen = pktLen*16 + v
		_ = i
	}
	actualPayload := string(data[pktStart+4 : pktStart+pktLen])
	t.Logf("packfile section header payload: %q", actualPayload)
	if actualPayload != "packfile\n" {
		t.Errorf("expected 'packfile\\n' section header, got %q", actualPayload)
	}

	// Next byte after the section header pkt-line should be the start of
	// a sideband pkt-line (band byte 0x01 for packfile data).
	sbStart := pktStart + pktLen
	sbLenStr := string(data[sbStart : sbStart+4])
	t.Logf("first sideband pkt-line length: %q", sbLenStr)
	// The payload starts with band byte 0x01.
	if data[sbStart+4] != 0x01 {
		t.Errorf("expected sideband band byte 0x01, got 0x%02x", data[sbStart+4])
	}

	// The sideband payload should start with PACK signature.
	packSig := string(data[sbStart+5 : sbStart+9])
	t.Logf("pack signature: %q", packSig)
	if packSig != "PACK" {
		t.Errorf("expected PACK signature, got %q", packSig)
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
