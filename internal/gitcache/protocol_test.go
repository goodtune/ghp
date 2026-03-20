package gitcache

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/gitprotocolio"
)

func TestParseCommands_LsRefsAndFetch(t *testing.T) {
	// Build a protocol v2 request with ls-refs followed by fetch.
	var buf bytes.Buffer
	writeChunk := func(c *gitprotocolio.ProtocolV2RequestChunk) {
		buf.Write(c.EncodeToPktLine())
	}

	// ls-refs command: command, delimiter (end caps), arguments, flush (end args).
	writeChunk(&gitprotocolio.ProtocolV2RequestChunk{Command: "ls-refs"})
	writeChunk(&gitprotocolio.ProtocolV2RequestChunk{EndCapability: true}) // delimiter
	writeChunk(&gitprotocolio.ProtocolV2RequestChunk{Argument: []byte("peel")})
	writeChunk(&gitprotocolio.ProtocolV2RequestChunk{Argument: []byte("symrefs")})
	writeChunk(&gitprotocolio.ProtocolV2RequestChunk{EndArgument: true}) // flush → back to Begin

	// fetch command: command, delimiter, arguments, flush.
	writeChunk(&gitprotocolio.ProtocolV2RequestChunk{Command: "fetch"})
	writeChunk(&gitprotocolio.ProtocolV2RequestChunk{EndCapability: true}) // delimiter
	writeChunk(&gitprotocolio.ProtocolV2RequestChunk{Argument: []byte("want abc123def456abc123def456abc123def456abc1")})
	writeChunk(&gitprotocolio.ProtocolV2RequestChunk{Argument: []byte("want-ref refs/heads/main")})
	writeChunk(&gitprotocolio.ProtocolV2RequestChunk{Argument: []byte("have 1234567890abcdef1234567890abcdef12345678")})
	writeChunk(&gitprotocolio.ProtocolV2RequestChunk{EndArgument: true}) // flush → back to Begin

	// Final flush signals end of request.
	writeChunk(&gitprotocolio.ProtocolV2RequestChunk{EndRequest: true})

	commands, err := ParseCommands(&buf)
	if err != nil {
		t.Fatalf("ParseCommands: %v", err)
	}

	if len(commands) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(commands))
	}

	if commands[0].Name != "ls-refs" {
		t.Errorf("command 0: expected ls-refs, got %s", commands[0].Name)
	}
	if commands[1].Name != "fetch" {
		t.Errorf("command 1: expected fetch, got %s", commands[1].Name)
	}
}

func TestParseCommands_RejectsUnknown(t *testing.T) {
	var buf bytes.Buffer
	chunk := &gitprotocolio.ProtocolV2RequestChunk{Command: "push"}
	buf.Write(chunk.EncodeToPktLine())
	end := &gitprotocolio.ProtocolV2RequestChunk{EndRequest: true}
	buf.Write(end.EncodeToPktLine())

	_, err := ParseCommands(&buf)
	if err == nil {
		t.Fatal("expected error for unknown command")
	}
}

func TestParseFetchWants(t *testing.T) {
	hash1 := "abc123def456abc123def456abc123def456abc1"
	hash2 := "def456abc123def456abc123def456abc123def4"

	cmd := Command{
		Name: "fetch",
		Chunks: []*gitprotocolio.ProtocolV2RequestChunk{
			{Command: "fetch"},
			{Argument: []byte("want " + hash1)},
			{Argument: []byte("want " + hash2)},
			{Argument: []byte("want-ref refs/heads/main")},
			{Argument: []byte("want-ref refs/tags/v1.0")},
			{Argument: []byte("thin-pack")}, // non-want argument, ignored
		},
	}

	hashes, refs, err := ParseFetchWants(cmd)
	if err != nil {
		t.Fatalf("ParseFetchWants: %v", err)
	}

	if len(hashes) != 2 {
		t.Fatalf("expected 2 hashes, got %d", len(hashes))
	}
	if hashes[0] != plumbing.NewHash(hash1) {
		t.Errorf("hash 0: got %s, want %s", hashes[0], hash1)
	}
	if hashes[1] != plumbing.NewHash(hash2) {
		t.Errorf("hash 1: got %s, want %s", hashes[1], hash2)
	}

	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d", len(refs))
	}
	if refs[0] != "refs/heads/main" {
		t.Errorf("ref 0: got %s, want refs/heads/main", refs[0])
	}
	if refs[1] != "refs/tags/v1.0" {
		t.Errorf("ref 1: got %s, want refs/tags/v1.0", refs[1])
	}
}

func TestParseFetchHaves(t *testing.T) {
	hash1 := "1234567890abcdef1234567890abcdef12345678"
	cmd := Command{
		Name: "fetch",
		Chunks: []*gitprotocolio.ProtocolV2RequestChunk{
			{Command: "fetch"},
			{Argument: []byte("want abc123def456abc123def456abc123def456abc1")},
			{Argument: []byte("have " + hash1)},
			{Argument: []byte("done")},
		},
	}

	haves := ParseFetchHaves(cmd)
	if len(haves) != 1 {
		t.Fatalf("expected 1 have, got %d", len(haves))
	}
	if haves[0] != plumbing.NewHash(hash1) {
		t.Errorf("have 0: got %s, want %s", haves[0], hash1)
	}
}

func TestParseLsRefsResponse(t *testing.T) {
	hash := "abc123def456abc123def456abc123def456abc1"
	chunks := []*gitprotocolio.ProtocolV2ResponseChunk{
		{Response: []byte(hash + " refs/heads/main\n")},
		{Response: []byte("def456abc123def456abc123def456abc123def4 refs/tags/v1.0\n")},
		{Delimiter: true},           // should be skipped
		{Response: nil},             // should be skipped
	}

	refs, err := ParseLsRefsResponse(chunks)
	if err != nil {
		t.Fatalf("ParseLsRefsResponse: %v", err)
	}

	if len(refs) != 2 {
		t.Fatalf("expected 2 refs, got %d", len(refs))
	}
	if refs["refs/heads/main"] != plumbing.NewHash(hash) {
		t.Errorf("main ref hash mismatch")
	}
}

func TestWriteInfoRefsResponse(t *testing.T) {
	w := httptest.NewRecorder()
	WriteInfoRefsResponse(w)

	if w.Code != 200 {
		t.Errorf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/x-git-upload-pack-advertisement" {
		t.Errorf("unexpected Content-Type: %s", ct)
	}
	if w.Body.Len() == 0 {
		t.Error("empty response body")
	}
}
