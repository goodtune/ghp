package securestore

// The tpm tier seals the DEK to this machine's TPM 2.0. The parent is an ECC
// P-256 storage root key (SRK) created in the owner hierarchy with empty auth
// on every call and never persisted; the same template and hierarchy seed
// always derive the same key. No PCR policy is bound, so firmware and OS
// updates do not lock the key out. Every path flushes the SRK and any loaded
// object before it returns.

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Reasons the tpm tier is unavailable. Each one is errors.Is ErrUnavailable.
var (
	ErrTPMOwnerAuthSet      = fmt.Errorf("%w: tpm owner hierarchy auth is set; cannot use an empty-auth SRK", ErrUnavailable)
	ErrTPMHierarchyDisabled = fmt.Errorf("%w: tpm storage hierarchy is disabled", ErrUnavailable)
	ErrTPMLockout           = fmt.Errorf("%w: tpm is in dictionary-attack lockout", ErrUnavailable)
)

const (
	tpmaPermanentOwnerAuthSet = 0x1   // TPMA_PERMANENT bit 0
	tpmaPermanentInLockout    = 0x200 // TPMA_PERMANENT bit 9 (bit 10, 0x400, is tpmGeneratedEPS)
	tpmaStartupClearSHEnable  = 0x2   // TPMA_STARTUP_CLEAR bit 1
	tpmBlobVersion            = 1
	tpmBlobTemplate           = "ecc-srk"
)

// tpmBlob is the wrapped key: the sealed object's public and private areas.
// Private is encrypted under the SRK seed, so it is useless on another TPM.
type tpmBlob struct {
	Version  int    `json:"v"`
	Template string `json:"template"`
	Public   []byte `json:"public"`  // tpm2.Marshal(TPM2BPublic)
	Private  []byte `json:"private"` // tpm2.Marshal(TPM2BPrivate)
}

func checkTPMProperties(permanent, startupClear uint32) error {
	switch {
	case permanent&tpmaPermanentOwnerAuthSet != 0:
		return ErrTPMOwnerAuthSet
	case permanent&tpmaPermanentInLockout != 0:
		return ErrTPMLockout
	case startupClear&tpmaStartupClearSHEnable == 0:
		return ErrTPMHierarchyDisabled
	}
	return nil
}

func probeTPM(t transport.TPM) error {
	perm, err := tpmProperty(t, tpm2.TPMPTPermanent)
	if err != nil {
		return err
	}
	sc, err := tpmProperty(t, tpm2.TPMPTStartupClear)
	if err != nil {
		return err
	}
	return checkTPMProperties(perm, sc)
}

func tpmProperty(t transport.TPM, p tpm2.TPMPT) (uint32, error) {
	rsp, err := withRetry(func() (*tpm2.GetCapabilityResponse, error) {
		return tpm2.GetCapability{Capability: tpm2.TPMCapTPMProperties, Property: uint32(p), PropertyCount: 1}.Execute(t)
	})
	if err != nil {
		return 0, fmt.Errorf("tpm GetCapability: %w", err)
	}
	props, err := rsp.CapabilityData.Data.TPMProperties()
	if err != nil {
		return 0, err
	}
	for _, tp := range props.TPMProperty {
		if tp.Property == p {
			return tp.Value, nil
		}
	}
	return 0, fmt.Errorf("tpm property %v not returned", p)
}

// classifyTPMError maps TPM return codes onto sentinels. tpm2.TPMRC implements
// errors.Is against the base code, so format-1 handle/parameter indices are ignored.
func classifyTPMError(err error) error {
	switch {
	case errors.Is(err, tpm2.TPMRCBadAuth), errors.Is(err, tpm2.TPMRCAuthFail):
		return fmt.Errorf("%w (%v)", ErrTPMOwnerAuthSet, err)
	case errors.Is(err, tpm2.TPMRCHierarchy):
		return fmt.Errorf("%w (%v)", ErrTPMHierarchyDisabled, err)
	case errors.Is(err, tpm2.TPMRCLockout):
		return fmt.Errorf("%w (%v)", ErrTPMLockout, err)
	case errors.Is(err, tpm2.TPMRCIntegrity):
		return fmt.Errorf("%w: tpm rejected the sealed blob (another TPM, or the TPM was cleared): %v", ErrForeignKey, err)
	}
	return err
}

func withRetry[T any](f func() (T, error)) (T, error) {
	for attempt := 1; ; attempt++ {
		v, err := f()
		if err == nil || attempt == 3 || !(errors.Is(err, tpm2.TPMRCRetry) || errors.Is(err, tpm2.TPMRCYielded)) {
			return v, err
		}
		time.Sleep(time.Duration(attempt) * 20 * time.Millisecond)
	}
}

// createSRK creates (never persists) the ECC P-256 SRK in the owner hierarchy.
// Fixed template + fixed hierarchy seed derive the same key every time.
func createSRK(t transport.TPM) (*tpm2.NamedHandle, func(), error) {
	rsp, err := withRetry(func() (*tpm2.CreatePrimaryResponse, error) {
		return tpm2.CreatePrimary{
			PrimaryHandle: tpm2.AuthHandle{Handle: tpm2.TPMRHOwner, Auth: tpm2.PasswordAuth(nil)},
			InPublic:      tpm2.New2B(tpm2.ECCSRKTemplate),
		}.Execute(t)
	})
	if err != nil {
		return nil, nil, classifyTPMError(err)
	}
	flush := func() { _, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(t) }
	return &tpm2.NamedHandle{Handle: rsp.ObjectHandle, Name: rsp.Name}, flush, nil
}

type tpmProtector struct {
	open func() (transport.TPMCloser, error)
}

func (p *tpmProtector) Name() string { return TierTPM }

func (p *tpmProtector) Wrap(dek []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, errors.New("tpm: data key must be 32 bytes")
	}
	t, err := p.open()
	if err != nil {
		return nil, fmt.Errorf("%w: opening tpm: %v", ErrUnavailable, err)
	}
	defer t.Close()
	parent, flush, err := createSRK(t)
	if err != nil {
		return nil, err
	}
	defer flush()
	sealed := tpm2.TPMTPublic{
		Type:             tpm2.TPMAlgKeyedHash,
		NameAlg:          tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{FixedTPM: true, FixedParent: true, UserWithAuth: true, NoDA: true},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash,
			&tpm2.TPMSKeyedHashParms{Scheme: tpm2.TPMTKeyedHashScheme{Scheme: tpm2.TPMAlgNull}}),
	}
	rsp, err := withRetry(func() (*tpm2.CreateResponse, error) {
		return tpm2.Create{
			ParentHandle: tpm2.AuthHandle{Handle: parent.Handle, Name: parent.Name, Auth: tpm2.PasswordAuth(nil)},
			InSensitive: tpm2.TPM2BSensitiveCreate{Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: dek}),
			}},
			InPublic: tpm2.New2B(sealed),
		}.Execute(t)
	})
	if err != nil {
		return nil, fmt.Errorf("tpm Create: %w", classifyTPMError(err))
	}
	return json.Marshal(tpmBlob{Version: tpmBlobVersion, Template: tpmBlobTemplate,
		Public: tpm2.Marshal(rsp.OutPublic), Private: tpm2.Marshal(rsp.OutPrivate)})
}

func (p *tpmProtector) Unwrap(wrapped []byte) ([]byte, error) {
	var b tpmBlob
	if err := json.Unmarshal(wrapped, &b); err != nil {
		return nil, fmt.Errorf("tpm: decoding wrapped key: %w", err)
	}
	if b.Version != tpmBlobVersion || b.Template != tpmBlobTemplate {
		return nil, fmt.Errorf("%w: tpm blob version %d template %q is not supported", ErrForeignKey, b.Version, b.Template)
	}
	pub, err := tpm2.Unmarshal[tpm2.TPM2BPublic](b.Public)
	if err != nil {
		return nil, fmt.Errorf("tpm: decoding public area: %w", err)
	}
	priv, err := tpm2.Unmarshal[tpm2.TPM2BPrivate](b.Private)
	if err != nil {
		return nil, fmt.Errorf("tpm: decoding private area: %w", err)
	}
	t, err := p.open()
	if err != nil {
		return nil, fmt.Errorf("%w: opening tpm: %v", ErrUnavailable, err)
	}
	defer t.Close()
	parent, flush, err := createSRK(t)
	if err != nil {
		return nil, err
	}
	defer flush()
	loaded, err := withRetry(func() (*tpm2.LoadResponse, error) {
		return tpm2.Load{
			ParentHandle: tpm2.AuthHandle{Handle: parent.Handle, Name: parent.Name, Auth: tpm2.PasswordAuth(nil)},
			InPrivate:    *priv,
			InPublic:     *pub,
		}.Execute(t)
	})
	if err != nil {
		return nil, fmt.Errorf("tpm Load: %w", classifyTPMError(err))
	}
	defer func() { _, _ = tpm2.FlushContext{FlushHandle: loaded.ObjectHandle}.Execute(t) }()
	out, err := withRetry(func() (*tpm2.UnsealResponse, error) {
		return tpm2.Unseal{ItemHandle: tpm2.AuthHandle{Handle: loaded.ObjectHandle, Name: loaded.Name, Auth: tpm2.PasswordAuth(nil)}}.Execute(t)
	})
	if err != nil {
		return nil, fmt.Errorf("tpm Unseal: %w", classifyTPMError(err))
	}
	return out.OutData.Buffer, nil
}

func tpmTier(open func() (transport.TPMCloser, error)) Tier {
	return Tier{
		Name: TierTPM,
		Probe: func() error {
			t, err := open()
			if err != nil {
				return fmt.Errorf("%w: opening tpm: %v", ErrUnavailable, err)
			}
			defer t.Close()
			return probeTPM(t)
		},
		Open: func(string) KeyProtector { return &tpmProtector{open: open} },
	}
}

// TPMTier returns the tpm tier backed by the host TPM.
func TPMTier() Tier { return tpmTier(openTPM) }
