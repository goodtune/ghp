//go:build windows

package securestore

import (
	"bytes"
	"testing"
)

func TestDPAPIProtector_RoundTrip(t *testing.T) {
	tier := DPAPITier()
	if tier.Name != TierDPAPI {
		t.Fatalf("tier.Name = %q, want %q", tier.Name, TierDPAPI)
	}
	if err := tier.Probe(); err != nil {
		t.Fatalf("Probe() = %v, want nil", err)
	}
	p := tier.Open("")
	if p.Name() != TierDPAPI {
		t.Fatalf("Name() = %q, want %q", p.Name(), TierDPAPI)
	}
	dek := bytes.Repeat([]byte{0x42}, 32)
	wrapped, err := p.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap() = %v", err)
	}
	if bytes.Contains(wrapped, dek) {
		t.Fatal("Wrap() output contains the plain key")
	}
	got, err := p.Unwrap(wrapped)
	if err != nil {
		t.Fatalf("Unwrap() = %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatalf("Unwrap() = %x, want %x", got, dek)
	}

	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := p.Unwrap(tampered); err == nil {
		t.Fatal("Unwrap(tampered) = nil error, want an error")
	}
	if _, err := p.Wrap(make([]byte, 16)); err == nil {
		t.Fatal("Wrap(16 bytes) = nil error, want an error")
	}
}
