// Package securestore protects the data-encryption key (DEK) of a local
// secret cache with the strongest key protector the host offers.
//
// Tiers, strongest first: tpm (a TPM 2.0 sealed key), dpapi (Windows Data
// Protection API), keychain (the macOS login keychain) and file. The file
// tier is always available and protects nothing beyond the permissions of
// the file that holds the key: anyone who can read that file can read the
// key.
package securestore

import (
	"errors"
	"fmt"
	"sort"
)

// KeyProtector wraps and unwraps a data-encryption key.
type KeyProtector interface {
	// Name returns the tier name of the protector (for example "tpm").
	Name() string
	// Wrap protects dek and returns the wrapped form. It never modifies dek.
	Wrap(dek []byte) ([]byte, error)
	// Unwrap returns the plain DEK from a value Wrap returned.
	Unwrap(wrapped []byte) ([]byte, error)
}

// Tier names and the automatic selection preference.
const (
	TierTPM        = "tpm"
	TierDPAPI      = "dpapi"
	TierKeychain   = "keychain"
	TierFile       = "file"
	PreferenceAuto = "auto"
)

var (
	// ErrUnavailable means a tier exists but cannot be used on this host now.
	ErrUnavailable = errors.New("securestore: protector unavailable")
	// ErrUnknownTier means the tier name is not one this build knows.
	ErrUnknownTier = errors.New("securestore: unknown tier")
	// ErrForeignKey means the wrapped key was made on another device.
	ErrForeignKey = errors.New("securestore: wrapped key was made on another device")
)

// Strength ranks a tier name: tpm 3, dpapi 2, keychain 1, file 0, and -1
// for any other name.
func Strength(name string) int {
	switch name {
	case TierTPM:
		return 3
	case TierDPAPI:
		return 2
	case TierKeychain:
		return 1
	case TierFile:
		return 0
	default:
		return -1
	}
}

// Tier describes one key protector tier.
type Tier struct {
	// Name is the tier name; Strength(Name) must be >= 0.
	Name string
	// Probe returns nil when the tier is usable now.
	Probe func() error
	// Open returns the tier's protector for scope, the cache directory path
	// (the keychain tier derives its account name from it).
	Open func(scope string) KeyProtector
}

// Protectors is an ordered set of tiers, strongest first.
type Protectors struct {
	tiers []Tier
}

// NewProtectors returns the tiers sorted by Strength, strongest first. It
// panics when a tier name has no strength.
func NewProtectors(tiers ...Tier) *Protectors {
	sorted := make([]Tier, len(tiers))
	copy(sorted, tiers)
	for _, t := range sorted {
		if Strength(t.Name) < 0 {
			panic(fmt.Sprintf("securestore: tier %q has no strength", t.Name))
		}
	}
	sort.SliceStable(sorted, func(i, j int) bool {
		return Strength(sorted[i].Name) > Strength(sorted[j].Name)
	})
	return &Protectors{tiers: sorted}
}

// Default returns the tiers this build supports on this platform.
func Default() *Protectors {
	return NewProtectors(FileTier())
}

// Names returns the tier names, strongest first.
func (p *Protectors) Names() []string {
	names := make([]string, 0, len(p.tiers))
	for _, t := range p.tiers {
		names = append(names, t.Name)
	}
	return names
}

func (p *Protectors) lookup(name string) (Tier, bool) {
	for _, t := range p.tiers {
		if t.Name == name {
			return t, true
		}
	}
	return Tier{}, false
}

// Available returns nil when the named tier is usable now. It returns
// ErrUnknownTier for a name not in the set, and wraps a probe failure with
// ErrUnavailable.
func (p *Protectors) Available(name string) error {
	t, ok := p.lookup(name)
	if !ok {
		return fmt.Errorf("%w: %q", ErrUnknownTier, name)
	}
	if err := t.Probe(); err != nil {
		if errors.Is(err, ErrUnavailable) {
			return err
		}
		return fmt.Errorf("%w: %s: %v", ErrUnavailable, name, err)
	}
	return nil
}

// Open returns the named tier's protector for scope without probing it.
func (p *Protectors) Open(name, scope string) (KeyProtector, error) {
	t, ok := p.lookup(name)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownTier, name)
	}
	return t.Open(scope), nil
}

// Select returns a protector for scope. A preference of "" or "auto" picks
// the strongest available tier; any other preference must name an
// available tier.
func (p *Protectors) Select(preference, scope string) (KeyProtector, error) {
	if preference == "" || preference == PreferenceAuto {
		for _, t := range p.tiers {
			if p.Available(t.Name) == nil {
				return t.Open(scope), nil
			}
		}
		return nil, fmt.Errorf("%w: no tier is usable", ErrUnavailable)
	}
	if err := p.Available(preference); err != nil {
		return nil, err
	}
	return p.Open(preference, scope)
}

// AvailableAtLeast returns a protector for every available tier with
// Strength >= Strength(minTier), strongest first. A minTier of "" returns
// every available tier.
func (p *Protectors) AvailableAtLeast(minTier, scope string) []KeyProtector {
	floor := Strength(minTier)
	out := make([]KeyProtector, 0, len(p.tiers))
	for _, t := range p.tiers {
		if Strength(t.Name) < floor {
			continue
		}
		if p.Available(t.Name) != nil {
			continue
		}
		out = append(out, t.Open(scope))
	}
	return out
}

// Available reports whether the named tier of Default is usable now.
func Available(name string) error {
	return Default().Available(name)
}

// Select returns a protector from Default; see Protectors.Select.
func Select(preference, scope string) (KeyProtector, error) {
	return Default().Select(preference, scope)
}
