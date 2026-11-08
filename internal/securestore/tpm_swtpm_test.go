//go:build !windows

package securestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
)

// TestTPMProtector_SWTPM seals and unseals against a real swtpm instance:
//
//	swtpm socket --tpm2 --tpmstate dir=$D --server type=unixio,path=$D/sock \
//	  --ctrl type=unixio,path=$D/ctrl --flags startup-clear
//	GHP_TEST_SWTPM=$D/sock GHP_TEST_SWTPM_CTRL=$D/ctrl go test ./internal/securestore/ -run SWTPM
func TestTPMProtector_SWTPM(t *testing.T) {
	sock, ctrl := os.Getenv("GHP_TEST_SWTPM"), os.Getenv("GHP_TEST_SWTPM_CTRL")
	if sock == "" || ctrl == "" {
		t.Skip("GHP_TEST_SWTPM / GHP_TEST_SWTPM_CTRL not set; skipping swtpm seal/unseal test")
	}
	open := func() (transport.TPMCloser, error) { return linuxudstpm.Open(sock) }
	tier := tpmTier(open)
	dek := bytes.Repeat([]byte{0x42}, 32)

	if err := tier.Probe(); err != nil {
		t.Fatalf("Probe() = %v, want nil", err)
	}
	assertNoTransientHandles(t, sock)

	w1, err := tier.Open("").Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap() #1: %v", err)
	}
	w2, err := tier.Open("").Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap() #2: %v", err)
	}
	if bytes.Equal(w1, w2) {
		t.Fatal("two Wrap() calls returned identical blobs; sealing must be randomised")
	}
	assertNoTransientHandles(t, sock)

	swtpmPowerCycle(t, ctrl, sock)

	got, err := tier.Open("").Unwrap(w1)
	if err != nil {
		t.Fatalf("Unwrap() after power cycle: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("Unwrap() after power cycle = %x, want %x", got, dek)
	}
	assertNoTransientHandles(t, sock)

	var b tpmBlob
	if err := json.Unmarshal(w1, &b); err != nil {
		t.Fatalf("decoding blob: %v", err)
	}
	b.Private[len(b.Private)-1] ^= 0xff
	tampered, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tier.Open("").Unwrap(tampered); !errors.Is(err, ErrForeignKey) {
		t.Fatalf("Unwrap(tampered) = %v, want errors.Is ErrForeignKey", err)
	}
	assertNoTransientHandles(t, sock)
}

// swtpmPowerCycle sends CMD_INIT (00 00 00 02, flags 00 00 00 00) on the
// control socket, expects a 4-byte all-zero result, then issues
// TPM2_Startup(CLEAR) on the data socket. Transient objects do not survive.
func swtpmPowerCycle(t *testing.T, ctrl, sock string) {
	t.Helper()
	c, err := net.Dial("unix", ctrl)
	if err != nil {
		t.Fatalf("dialing swtpm control socket: %v", err)
	}
	defer func() { _ = c.Close() }()
	if _, err := c.Write([]byte{0, 0, 0, 2, 0, 0, 0, 0}); err != nil {
		t.Fatalf("writing CMD_INIT: %v", err)
	}
	resp := make([]byte, 4)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("reading CMD_INIT result: %v", err)
	}
	if !bytes.Equal(resp, []byte{0, 0, 0, 0}) {
		t.Fatalf("CMD_INIT result = %x, want 00000000", resp)
	}
	tpm, err := linuxudstpm.Open(sock)
	if err != nil {
		t.Fatalf("opening swtpm: %v", err)
	}
	defer func() { _ = tpm.Close() }()
	if _, err := (tpm2.Startup{StartupType: tpm2.TPMSUClear}).Execute(tpm); err != nil {
		t.Fatalf("TPM2_Startup(CLEAR): %v", err)
	}
}

// assertNoTransientHandles fails when any transient object is loaded.
func assertNoTransientHandles(t *testing.T, sock string) {
	t.Helper()
	tpm, err := linuxudstpm.Open(sock)
	if err != nil {
		t.Fatalf("opening swtpm: %v", err)
	}
	defer func() { _ = tpm.Close() }()
	rsp, err := tpm2.GetCapability{Capability: tpm2.TPMCapHandles, Property: 0x80000000, PropertyCount: 16}.Execute(tpm)
	if err != nil {
		t.Fatalf("GetCapability(handles): %v", err)
	}
	handles, err := rsp.CapabilityData.Data.Handles()
	if err != nil {
		t.Fatalf("decoding handles: %v", err)
	}
	if len(handles.Handle) != 0 {
		t.Fatalf("%d transient handles left loaded: %v", len(handles.Handle), handles.Handle)
	}
}
