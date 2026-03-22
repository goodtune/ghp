package gitcache

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/gitprotocolio"
)

// Command represents a parsed Git protocol v2 command (ls-refs or fetch)
// along with its raw request chunks for forwarding to upstream.
type Command struct {
	Name   string
	Chunks []*gitprotocolio.ProtocolV2RequestChunk
}

// ParseCommands reads a Git protocol v2 request body and returns the
// individual commands. Each command consists of a command chunk followed
// by capability/argument chunks. Commands are separated by flush packets
// (EndArgument); the final flush (EndRequest) terminates the stream.
func ParseCommands(r io.Reader) ([]Command, error) {
	var commands []Command
	scanner := gitprotocolio.NewProtocolV2Request(r)

	for {
		var chunks []*gitprotocolio.ProtocolV2RequestChunk
		for scanner.Scan() {
			c := copyRequestChunk(scanner.Chunk())
			if c.EndRequest || c.EndArgument {
				// Include the terminating chunk so that
				// EncodeCommandsToReader produces a well-formed request
				// with the required flush/delimiter pkt-lines.
				chunks = append(chunks, c)
				break
			}
			chunks = append(chunks, c)
		}
		// A command must have at least a command chunk plus a terminator.
		if len(chunks) <= 1 || scanner.Err() != nil {
			break
		}

		// Verify the last chunk is a proper terminator (EndArgument or EndRequest).
		// A truncated request body (EOF without flush pkt-line) would produce
		// chunks without a terminator, which we must reject.
		last := chunks[len(chunks)-1]
		if !last.EndArgument && !last.EndRequest {
			return nil, fmt.Errorf("truncated command: missing terminator")
		}

		name := chunks[0].Command
		switch name {
		case "ls-refs", "fetch":
			// accepted
		default:
			return nil, fmt.Errorf("unrecognised command: %s", name)
		}
		commands = append(commands, Command{Name: name, Chunks: chunks})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse protocol v2 request: %w", err)
	}
	return commands, nil
}

// ParseFetchWants extracts the object hashes and ref names from a fetch
// command's "want <hash>" and "want-ref <refname>" arguments.
func ParseFetchWants(cmd Command) (hashes []plumbing.Hash, refs []string, err error) {
	for _, c := range cmd.Chunks {
		if c.Argument == nil {
			continue
		}
		s := string(c.Argument)
		switch {
		case strings.HasPrefix(s, "want "):
			parts := strings.Fields(s)
			if len(parts) < 2 {
				return nil, nil, fmt.Errorf("malformed want: %q", s)
			}
			hashes = append(hashes, plumbing.NewHash(parts[1]))
		case strings.HasPrefix(s, "want-ref "):
			parts := strings.Fields(s)
			if len(parts) < 2 {
				return nil, nil, fmt.Errorf("malformed want-ref: %q", s)
			}
			refs = append(refs, parts[1])
		}
	}
	return hashes, refs, nil
}

// ParseFetchHaves extracts the "have <hash>" arguments from a fetch command.
func ParseFetchHaves(cmd Command) []plumbing.Hash {
	var haves []plumbing.Hash
	for _, c := range cmd.Chunks {
		if c.Argument == nil {
			continue
		}
		s := string(c.Argument)
		if strings.HasPrefix(s, "have ") {
			parts := strings.Fields(s)
			if len(parts) >= 2 {
				haves = append(haves, plumbing.NewHash(parts[1]))
			}
		}
	}
	return haves
}

// ParseLsRefsResponse parses an ls-refs response from upstream into a
// map of ref name → object hash.
func ParseLsRefsResponse(chunks []*gitprotocolio.ProtocolV2ResponseChunk) (map[string]plumbing.Hash, error) {
	refs := make(map[string]plumbing.Hash)
	for _, ch := range chunks {
		if ch.Response == nil {
			continue
		}
		line := string(ch.Response)
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil, fmt.Errorf("malformed ls-refs response line: %q", line)
		}
		refName := fields[1]
		// Strip NUL-separated attributes (e.g. symref-target:, peeled:).
		if i := strings.IndexByte(refName, 0); i >= 0 {
			refName = refName[:i]
		}
		refs[refName] = plumbing.NewHash(fields[0])
	}
	return refs, nil
}

// WriteInfoRefsResponse writes the synthetic capability advertisement for
// a cached repository's /info/refs?service=git-upload-pack endpoint.
func WriteInfoRefsResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
	chunks := []*gitprotocolio.InfoRefsResponseChunk{
		{ProtocolVersion: 2},
		{Capabilities: []string{"ls-refs"}},
		{Capabilities: []string{"fetch=filter shallow"}},
		{Capabilities: []string{"server-option"}},
		{EndOfRequest: true},
	}
	for _, pkt := range chunks {
		w.Write(pkt.EncodeToPktLine())
	}
}

// WriteResponseChunks writes protocol v2 response chunks to w.
func WriteResponseChunks(w io.Writer, chunks []*gitprotocolio.ProtocolV2ResponseChunk) error {
	for _, ch := range chunks {
		if _, err := w.Write(ch.EncodeToPktLine()); err != nil {
			return err
		}
	}
	return nil
}

// WriteError writes a Git protocol error packet.
func WriteError(w io.Writer, msg string) error {
	pkt := gitprotocolio.ErrorPacket(msg)
	_, err := w.Write(pkt.EncodeToPktLine())
	return err
}

// EncodeCommandsToReader serialises protocol v2 request chunks into an
// io.Reader suitable for forwarding to an upstream server.
func EncodeCommandsToReader(cmd Command) io.Reader {
	var buf bytes.Buffer
	for _, c := range cmd.Chunks {
		buf.Write(c.EncodeToPktLine())
	}
	return &buf
}

// MaybeGunzip returns a reader that decompresses gzip content if the
// Content-Encoding header indicates gzip, or the original body otherwise.
// The returned io.ReadCloser must be closed by the caller to release
// resources. Closing the returned reader closes both the gzip layer and
// the underlying request body.
func MaybeGunzip(r *http.Request) (io.ReadCloser, error) {
	if r.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			return nil, err
		}
		return &gzipReadCloser{gz: gz, body: r.Body}, nil
	}
	return r.Body, nil
}

// gzipReadCloser wraps a gzip.Reader so that Close closes both the gzip
// layer and the underlying body.
type gzipReadCloser struct {
	gz   *gzip.Reader
	body io.ReadCloser
}

func (g *gzipReadCloser) Read(p []byte) (int, error) { return g.gz.Read(p) }
func (g *gzipReadCloser) Close() error {
	gzErr := g.gz.Close()
	bodyErr := g.body.Close()
	if gzErr != nil {
		return gzErr
	}
	return bodyErr
}

func copyRequestChunk(c *gitprotocolio.ProtocolV2RequestChunk) *gitprotocolio.ProtocolV2RequestChunk {
	r := *c
	if r.Argument != nil {
		b := make([]byte, len(r.Argument))
		copy(b, r.Argument)
		r.Argument = b
	}
	return &r
}

func copyResponseChunk(c *gitprotocolio.ProtocolV2ResponseChunk) *gitprotocolio.ProtocolV2ResponseChunk {
	r := *c
	if r.Response != nil {
		b := make([]byte, len(r.Response))
		copy(b, r.Response)
		r.Response = b
	}
	return &r
}
