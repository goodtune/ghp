package securestore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

func TestCheckTPMProperties(t *testing.T) {
	tests := []struct {
		name         string
		permanent    uint32
		startupClear uint32
		want         error
	}{
		{"usable", 0, 0x2, nil},
		{"owner auth set", 0x1, 0x2, ErrTPMOwnerAuthSet},
		{"in lockout", 0x200, 0x2, ErrTPMLockout},
		{"tpmGeneratedEPS is not lockout", 0x400, 0x2, nil},
		{"storage hierarchy disabled", 0, 0, ErrTPMHierarchyDisabled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkTPMProperties(tt.permanent, tt.startupClear)
			if tt.want == nil {
				if err != nil {
					t.Fatalf("checkTPMProperties(%#x, %#x) = %v, want nil", tt.permanent, tt.startupClear, err)
				}
				return
			}
			if !errors.Is(err, tt.want) {
				t.Fatalf("checkTPMProperties(%#x, %#x) = %v, want %v", tt.permanent, tt.startupClear, err, tt.want)
			}
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("checkTPMProperties(%#x, %#x) = %v, want errors.Is ErrUnavailable", tt.permanent, tt.startupClear, err)
			}
		})
	}
}

func TestClassifyTPMError(t *testing.T) {
	plain := errors.New("x")
	tests := []struct {
		name string
		in   error
		want []error
	}{
		{"bad auth", tpm2.TPMRCBadAuth, []error{ErrTPMOwnerAuthSet, ErrUnavailable}},
		{"auth fail", tpm2.TPMRCAuthFail, []error{ErrTPMOwnerAuthSet, ErrUnavailable}},
		{"hierarchy", tpm2.TPMRCHierarchy, []error{ErrTPMHierarchyDisabled, ErrUnavailable}},
		{"lockout", tpm2.TPMRCLockout, []error{ErrTPMLockout, ErrUnavailable}},
		{"integrity", tpm2.TPMRCIntegrity, []error{ErrForeignKey}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyTPMError(tt.in)
			for _, w := range tt.want {
				if !errors.Is(got, w) {
					t.Errorf("classifyTPMError(%v) = %v, want errors.Is %v", tt.in, got, w)
				}
			}
		})
	}
	t.Run("integrity is not unavailable", func(t *testing.T) {
		if got := classifyTPMError(tpm2.TPMRCIntegrity); errors.Is(got, ErrUnavailable) {
			t.Fatalf("classifyTPMError(TPMRCIntegrity) = %v, must not be ErrUnavailable", got)
		}
	})
	t.Run("other errors unchanged", func(t *testing.T) {
		if got := classifyTPMError(plain); got != plain {
			t.Fatalf("classifyTPMError(%v) = %v, want the same error", plain, got)
		}
	})
}

func TestTPMTier_OpenFailureUnavailable(t *testing.T) {
	tier := tpmTier(func() (transport.TPMCloser, error) { return nil, os.ErrNotExist })
	if tier.Name != TierTPM {
		t.Fatalf("tier.Name = %q, want %q", tier.Name, TierTPM)
	}
	err := tier.Probe()
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Probe() = %v, want errors.Is ErrUnavailable", err)
	}
}

// failingTPM is a transport whose every command fails.
type failingTPM struct {
	err    error
	sends  int
	closed bool
}

func (f *failingTPM) Send([]byte) ([]byte, error) {
	f.sends++
	return nil, f.err
}

func (f *failingTPM) Close() error {
	f.closed = true
	return nil
}

func TestProbeTPM_TransportError(t *testing.T) {
	f := &failingTPM{err: errors.New("boom")}
	if err := probeTPM(f); err == nil {
		t.Fatal("probeTPM() = nil, want an error")
	}
	if f.sends != 1 {
		t.Fatalf("Send called %d times, want 1 (no retry on a transport error)", f.sends)
	}
}

func TestTPMTier_ProbeClosesTransport(t *testing.T) {
	f := &failingTPM{err: errors.New("boom")}
	tier := tpmTier(func() (transport.TPMCloser, error) { return f, nil })
	if err := tier.Probe(); err == nil {
		t.Fatal("Probe() = nil, want an error")
	}
	if !f.closed {
		t.Fatal("Probe() did not close the transport")
	}
}

func TestTPMProtector_RejectsBadInput(t *testing.T) {
	opened := false
	p := tpmTier(func() (transport.TPMCloser, error) {
		opened = true
		return nil, os.ErrNotExist
	}).Open("")
	if p.Name() != TierTPM {
		t.Fatalf("Name() = %q, want %q", p.Name(), TierTPM)
	}

	t.Run("wrap short key", func(t *testing.T) {
		if _, err := p.Wrap(make([]byte, 16)); err == nil {
			t.Fatal("Wrap(16 bytes) = nil error, want an error")
		}
	})
	t.Run("unwrap malformed json", func(t *testing.T) {
		_, err := p.Unwrap([]byte("{"))
		if err == nil {
			t.Fatal("Unwrap(\"{\") = nil error, want an error")
		}
		if errors.Is(err, ErrForeignKey) {
			t.Fatalf("Unwrap(\"{\") = %v, must not be ErrForeignKey", err)
		}
	})
	for _, b := range []tpmBlob{
		{Version: 2, Template: tpmBlobTemplate},
		{Version: tpmBlobVersion, Template: "rsa-srk"},
	} {
		t.Run(fmt.Sprintf("unwrap unsupported v%d %s", b.Version, b.Template), func(t *testing.T) {
			raw, err := json.Marshal(b)
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.Unwrap(raw)
			if !errors.Is(err, ErrForeignKey) {
				t.Fatalf("Unwrap(%s) = %v, want errors.Is ErrForeignKey", raw, err)
			}
			if !strings.Contains(err.Error(), "not supported") {
				t.Fatalf("Unwrap(%s) = %q, want it to contain %q", raw, err, "not supported")
			}
		})
	}
	if opened {
		t.Fatal("bad input reached the TPM transport")
	}
}

func TestTPMBlob_JSONFieldNames(t *testing.T) {
	raw, err := json.Marshal(tpmBlob{Version: tpmBlobVersion, Template: tpmBlobTemplate, Public: []byte{1}, Private: []byte{2}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"v":1,"template":"ecc-srk","public":"AQ==","private":"Ag=="}`
	if string(raw) != want {
		t.Fatalf("json = %s, want %s", raw, want)
	}
}

func TestDefault_IncludesTPMTier(t *testing.T) {
	got := Default().Names()
	want := []string{TierTPM, TierFile}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("Default().Names() = %v, want %v", got, want)
	}
}
