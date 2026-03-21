package gitcache

import (
	"bytes"
	"fmt"
	"io"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/format/packfile"
	"github.com/go-git/go-git/v5/plumbing/revlist"
	"github.com/go-git/go-git/v5/plumbing/storer"
	"github.com/google/gitprotocolio"
)

const (
	// packWindow controls the delta compression window size.
	// Higher values produce smaller packs but use more CPU/memory.
	packWindow = 10
)

// ServeFetchLocal generates a packfile containing the objects the client
// needs (wants minus haves) and writes the Git protocol v2 response.
//
// The response format is:
//   - "packfile" section header (no leading delimiter — delimiters only separate sections)
//   - Sideband-encoded packfile data (band 1)
//   - Flush packet
func ServeFetchLocal(w io.Writer, store storer.EncodedObjectStorer, wants []plumbing.Hash, haves []plumbing.Hash) error {
	// Compute the set of objects to send: everything reachable from
	// wants, excluding everything reachable from haves.
	objectHashes, err := revlist.Objects(store, wants, haves)
	if err != nil {
		return fmt.Errorf("compute object set: %w", err)
	}

	if len(objectHashes) == 0 {
		// Nothing to send — write an empty response.
		return writeEmptyFetchResponse(w)
	}

	// Generate the packfile into a buffer. We buffer because the
	// protocol requires us to sideband-encode it.
	var packBuf bytes.Buffer
	encoder := packfile.NewEncoder(&packBuf, store, false)
	if _, err := encoder.Encode(objectHashes, packWindow); err != nil {
		return fmt.Errorf("encode packfile: %w", err)
	}

	return writeFetchResponse(w, packBuf.Bytes())
}

// writeFetchResponse writes a Git protocol v2 fetch response containing
// the given packfile data. The format follows the git protocol v2 spec:
//
//	delimiter
//	"packfile\n"
//	sideband data (band 1 = packfile data)
//	flush
func writeFetchResponse(w io.Writer, packData []byte) error {
	// Write "packfile" section header as a response line.
	// Note: NO delimiter before the first (and only) section. In protocol v2,
	// delimiters separate sections, they don't precede the first one.
	sectionHeader := &gitprotocolio.ProtocolV2ResponseChunk{
		Response: []byte("packfile\n"),
	}
	if _, err := w.Write(sectionHeader.EncodeToPktLine()); err != nil {
		return err
	}

	// Write packfile data using sideband band 1 (packfile data).
	// Git sideband format: first byte is the band number, rest is payload.
	// Band 1 = pack data, Band 2 = progress, Band 3 = error.
	// Maximum sideband packet payload is 65516 bytes (65520 - 4 byte pkt-line header).
	const maxPayload = 65516 - 1 // -1 for sideband band byte
	for len(packData) > 0 {
		chunk := packData
		if len(chunk) > maxPayload {
			chunk = packData[:maxPayload]
		}
		packData = packData[len(chunk):]

		// Sideband packet: band byte (0x01) + data.
		pkt := make([]byte, 1+len(chunk))
		pkt[0] = 1 // band 1 = pack data
		copy(pkt[1:], chunk)

		resp := &gitprotocolio.ProtocolV2ResponseChunk{Response: pkt}
		if _, err := w.Write(resp.EncodeToPktLine()); err != nil {
			return err
		}
	}

	// Flush packet signals end of response.
	flush := &gitprotocolio.ProtocolV2ResponseChunk{EndResponse: true}
	_, err := w.Write(flush.EncodeToPktLine())
	return err
}

func writeEmptyFetchResponse(w io.Writer) error {
	// For an empty response (nothing to send), just write flush.
	flush := &gitprotocolio.ProtocolV2ResponseChunk{EndResponse: true}
	_, err := w.Write(flush.EncodeToPktLine())
	return err
}

// ResolveWantHashes resolves want-ref references to their object hashes
// using the local store, then combines with direct want hashes.
func ResolveWantHashes(store storer.EncodedObjectStorer, refStore storer.ReferenceStorer, wantHashes []plumbing.Hash, wantRefs []string) ([]plumbing.Hash, error) {
	result := make([]plumbing.Hash, len(wantHashes))
	copy(result, wantHashes)

	for _, refName := range wantRefs {
		ref, err := refStore.Reference(plumbing.ReferenceName(refName))
		if err != nil {
			return nil, fmt.Errorf("resolve want-ref %s: %w", refName, err)
		}
		result = append(result, ref.Hash())
	}

	return result, nil
}
