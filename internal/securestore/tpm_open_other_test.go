//go:build !linux && !windows

package securestore

import (
	"errors"
	"strings"
	"testing"
)

func TestTPMTier_StubProbePrefixedOnce(t *testing.T) {
	err := TPMTier().Probe()
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Probe() = %v, want errors.Is ErrUnavailable", err)
	}
	want := ErrUnavailable.Error() + ": no TPM transport on this platform"
	if err.Error() != want {
		t.Fatalf("Probe() = %q, want %q", err, want)
	}
	if n := strings.Count(err.Error(), ErrUnavailable.Error()); n != 1 {
		t.Fatalf("Probe() = %q: prefix appears %d times, want 1", err, n)
	}
}
