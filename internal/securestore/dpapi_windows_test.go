//go:build windows

package securestore

import (
	"bytes"
	"errors"
	"fmt"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
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

func TestClassifyDPAPIError(t *testing.T) {
	tests := []struct {
		name        string
		in          error
		wantForeign bool
	}{
		{"ERROR_INVALID_DATA", windows.ERROR_INVALID_DATA, true},
		{"NTE_BAD_DATA", syscall.Errno(0x80090005), true},
		{"NTE_BAD_KEY_STATE", syscall.Errno(0x8009000B), true},
		{"wrapped NTE_BAD_DATA", fmt.Errorf("call: %w", syscall.Errno(0x80090005)), true},
		{"ERROR_ACCESS_DENIED", windows.ERROR_ACCESS_DENIED, false},
		{"other", errors.New("boom"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyDPAPIError(tt.in)
			if errors.Is(got, ErrForeignKey) != tt.wantForeign {
				t.Fatalf("classifyDPAPIError(%v) = %v; errors.Is ErrForeignKey = %v, want %v", tt.in, got, !tt.wantForeign, tt.wantForeign)
			}
			if !errors.Is(got, tt.in) && !tt.wantForeign {
				t.Fatalf("classifyDPAPIError(%v) = %v, want it to wrap the cause", tt.in, got)
			}
			if errors.Is(got, ErrUnavailable) {
				t.Fatalf("classifyDPAPIError(%v) = %v, must not be ErrUnavailable", tt.in, got)
			}
		})
	}
}
