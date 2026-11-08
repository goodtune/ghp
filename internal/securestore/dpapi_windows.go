//go:build windows

package securestore

// The dpapi tier protects the DEK with the Windows Data Protection API in
// user scope: only the same Windows user on the same machine (or a roaming
// profile of that user) can unprotect it.

import (
	"bytes"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const dpapiDescription = "ghp git-credential cache key"

// dpapiEntropy is the fixed application entropy; other applications running
// as the same user must supply it too.
var dpapiEntropy = []byte("ghp-git-credential-cache-v1")

// CryptUnprotectData failures that retrying cannot fix: a corrupt blob, or
// one whose master key is gone (an admin password reset or a copied
// profile). x/sys declares the NTE codes as HRESULT handles; GetLastError
// returns them as errnos.
var (
	nteBadData     = syscall.Errno(windows.NTE_BAD_DATA)      // 0x80090005
	nteBadKeyState = syscall.Errno(windows.NTE_BAD_KEY_STATE) // 0x8009000B
)

// DPAPITier returns the dpapi tier.
func DPAPITier() Tier {
	return Tier{
		Name: TierDPAPI,
		Probe: func() error {
			probe := make([]byte, 32)
			wrapped, err := dpapiProtect(probe)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrUnavailable, err)
			}
			got, err := dpapiUnprotect(wrapped)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrUnavailable, err)
			}
			if !bytes.Equal(got, probe) {
				return fmt.Errorf("%w: dpapi round trip returned different data", ErrUnavailable)
			}
			return nil
		},
		Open: func(string) KeyProtector { return dpapiProtector{} },
	}
}

type dpapiProtector struct{}

func (dpapiProtector) Name() string { return TierDPAPI }

func (dpapiProtector) Wrap(dek []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, errors.New("dpapi: data key must be 32 bytes")
	}
	return dpapiProtect(dek)
}

func (dpapiProtector) Unwrap(wrapped []byte) ([]byte, error) {
	return dpapiUnprotect(wrapped)
}

func dpapiBlob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

// dpapiTake copies the system-allocated output blob, wipes it and frees it.
func dpapiTake(b *windows.DataBlob) []byte {
	if b.Data == nil {
		return nil
	}
	src := unsafe.Slice(b.Data, b.Size)
	out := append([]byte(nil), src...)
	clear(src)
	_, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(b.Data)))
	return out
}

func dpapiProtect(in []byte) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(dpapiDescription)
	if err != nil {
		return nil, err
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(dpapiBlob(in), name, dpapiBlob(dpapiEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("dpapi: CryptProtectData: %w", err)
	}
	return dpapiTake(&out), nil
}

func dpapiUnprotect(in []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(dpapiBlob(in), nil, dpapiBlob(dpapiEntropy), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, classifyDPAPIError(err)
	}
	return dpapiTake(&out), nil
}

// classifyDPAPIError maps the deterministic CryptUnprotectData failures to
// ErrForeignKey, so the cache is discarded and rebuilt (at or above the
// tier floor) instead of being reported unreadable on every call. Any other
// failure is returned wrapped.
func classifyDPAPIError(err error) error {
	if errors.Is(err, windows.ERROR_INVALID_DATA) || errors.Is(err, nteBadData) || errors.Is(err, nteBadKeyState) {
		return fmt.Errorf("%w: dpapi: CryptUnprotectData: %v", ErrForeignKey, err)
	}
	return fmt.Errorf("dpapi: CryptUnprotectData: %w", err)
}
