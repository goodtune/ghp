package securestore

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// xorProtector is a test-only KeyProtector that XORs every byte with 0x5a.
type xorProtector struct{ name string }

func (x xorProtector) Name() string { return x.name }

func (x xorProtector) Wrap(dek []byte) ([]byte, error) { return xorBytes(dek), nil }

func (x xorProtector) Unwrap(wrapped []byte) ([]byte, error) { return xorBytes(wrapped), nil }

func xorBytes(in []byte) []byte {
	out := make([]byte, len(in))
	for i, b := range in {
		out[i] = b ^ 0x5a
	}
	return out
}

func fakeTier(name string, probeErr error) Tier {
	return Tier{
		Name:  name,
		Probe: func() error { return probeErr },
		Open:  func(string) KeyProtector { return xorProtector{name: name} },
	}
}

func protectorNames(ps []KeyProtector) []string {
	names := make([]string, 0, len(ps))
	for _, p := range ps {
		names = append(names, p.Name())
	}
	return names
}

func TestStrength(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{"tpm", 3},
		{"dpapi", 2},
		{"keychain", 1},
		{"file", 0},
		{"vault", -1},
		{"", -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Strength(tt.name); got != tt.want {
				t.Errorf("Strength(%q) = %d, want %d", tt.name, got, tt.want)
			}
		})
	}
}

func TestNewProtectors_SortsStrongestFirst(t *testing.T) {
	p := NewProtectors(fakeTier("file", nil), fakeTier("tpm", nil), fakeTier("keychain", nil))
	want := []string{"tpm", "keychain", "file"}
	if got := p.Names(); !reflect.DeepEqual(got, want) {
		t.Errorf("Names() = %v, want %v", got, want)
	}
}

func TestNewProtectors_PanicsOnUnknownTier(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewProtectors with an unknown tier did not panic")
		}
	}()
	NewProtectors(fakeTier("vault", nil))
}

func TestSelect(t *testing.T) {
	probeFail := errors.New("no device")
	tests := []struct {
		name       string
		tiers      []Tier
		preference string
		want       string
		wantErr    error
	}{
		{
			name:       "auto skips unavailable tpm",
			tiers:      []Tier{fakeTier("tpm", probeFail), fakeTier("keychain", nil)},
			preference: PreferenceAuto,
			want:       "keychain",
		},
		{
			name:       "empty behaves as auto",
			tiers:      []Tier{fakeTier("tpm", probeFail), fakeTier("keychain", nil)},
			preference: "",
			want:       "keychain",
		},
		{
			name:       "explicit tpm with failing probe",
			tiers:      []Tier{fakeTier("tpm", probeFail), fakeTier("keychain", nil)},
			preference: TierTPM,
			wantErr:    ErrUnavailable,
		},
		{
			name:       "unknown tier",
			tiers:      []Tier{fakeTier("tpm", nil), fakeTier("file", nil)},
			preference: "vault",
			wantErr:    ErrUnknownTier,
		},
		{
			name:       "explicit file",
			tiers:      []Tier{fakeTier("tpm", nil), fakeTier("file", nil)},
			preference: TierFile,
			want:       "file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewProtectors(tt.tiers...).Select(tt.preference, "")
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Select(%q) error = %v, want errors.Is %v", tt.preference, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Select(%q) error = %v", tt.preference, err)
			}
			if got.Name() != tt.want {
				t.Errorf("Select(%q) = %q, want %q", tt.preference, got.Name(), tt.want)
			}
		})
	}
}

func TestAvailable_WrapsProbeError(t *testing.T) {
	probeFail := errors.New("no device")
	p := NewProtectors(fakeTier("tpm", probeFail), fakeTier("keychain", ErrUnavailable), fakeTier("file", nil))
	tests := []struct {
		name     string
		tier     string
		wantErrs []error
		wantMsg  string
	}{
		{"probe error wrapped", "tpm", []error{ErrUnavailable}, "securestore: protector unavailable: tpm: no device"},
		{"ErrUnavailable passed through", "keychain", []error{ErrUnavailable}, ""},
		{"unknown tier", "dpapi", []error{ErrUnknownTier}, ""},
		{"available", "file", nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Available(tt.tier)
			if tt.wantErrs == nil {
				if err != nil {
					t.Fatalf("Available(%q) error = %v", tt.tier, err)
				}
				return
			}
			for _, want := range tt.wantErrs {
				if !errors.Is(err, want) {
					t.Errorf("Available(%q) error = %v, want errors.Is %v", tt.tier, err, want)
				}
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("Available(%q) error = %q, want it to contain %q", tt.tier, err.Error(), tt.wantMsg)
			}
		})
	}
	if err := p.Available("keychain"); err != ErrUnavailable {
		t.Errorf("Available(keychain) = %v, want ErrUnavailable unchanged", err)
	}
}

func TestOpen(t *testing.T) {
	p := NewProtectors(fakeTier("tpm", errors.New("no device")), fakeTier("file", nil))
	got, err := p.Open("tpm", "")
	if err != nil {
		t.Fatalf("Open(tpm) error = %v (Open must not probe)", err)
	}
	if got.Name() != "tpm" {
		t.Errorf("Open(tpm).Name() = %q", got.Name())
	}
	if _, err := p.Open("vault", ""); !errors.Is(err, ErrUnknownTier) {
		t.Errorf("Open(vault) error = %v, want ErrUnknownTier", err)
	}
}

func TestAvailableAtLeast(t *testing.T) {
	fail := errors.New("no device")
	tests := []struct {
		name    string
		tiers   []Tier
		minTier string
		want    []string
	}{
		{
			name:    "keychain floor, only file available",
			tiers:   []Tier{fakeTier("tpm", fail), fakeTier("keychain", fail), fakeTier("file", nil)},
			minTier: TierKeychain,
			want:    []string{},
		},
		{
			name:    "no floor",
			tiers:   []Tier{fakeTier("tpm", fail), fakeTier("keychain", nil), fakeTier("file", nil)},
			minTier: "",
			want:    []string{"keychain", "file"},
		},
		{
			name:    "file floor, all available",
			tiers:   []Tier{fakeTier("tpm", nil), fakeTier("keychain", nil), fakeTier("file", nil)},
			minTier: TierFile,
			want:    []string{"tpm", "keychain", "file"},
		},
		{
			name:    "tpm floor, all available",
			tiers:   []Tier{fakeTier("tpm", nil), fakeTier("keychain", nil), fakeTier("file", nil)},
			minTier: TierTPM,
			want:    []string{"tpm"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := protectorNames(NewProtectors(tt.tiers...).AvailableAtLeast(tt.minTier, ""))
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AvailableAtLeast(%q) = %v, want %v", tt.minTier, got, tt.want)
			}
		})
	}
}

func TestDefault_IncludesFileTier(t *testing.T) {
	p, err := Select(PreferenceAuto, "")
	if err != nil {
		t.Fatalf("Select(auto) error = %v", err)
	}
	if p == nil {
		t.Fatal("Select(auto) returned nil protector")
	}
	if err := Available(TierFile); err != nil {
		t.Errorf("Available(file) error = %v", err)
	}
}

func TestFileProtector_RoundTrip(t *testing.T) {
	dek := bytes.Repeat([]byte{7}, 32)
	want := bytes.Repeat([]byte{7}, 32)
	p := FileTier().Open("")
	if p.Name() != TierFile {
		t.Errorf("Name() = %q, want %q", p.Name(), TierFile)
	}
	w, err := p.Wrap(dek)
	if err != nil {
		t.Fatalf("Wrap error = %v", err)
	}
	dek[0] = 9
	if w[0] != 7 {
		t.Errorf("Wrap did not copy its input: w[0] = %d", w[0])
	}
	got, err := p.Unwrap(w)
	if err != nil {
		t.Fatalf("Unwrap error = %v", err)
	}
	if !bytes.Equal(got, w) || !bytes.Equal(got, want) {
		t.Errorf("Unwrap = %v, want %v", got, want)
	}
	w[1] = 9
	if got[1] != 7 {
		t.Errorf("Unwrap did not copy its input: got[1] = %d", got[1])
	}
	if err := FileTier().Probe(); err != nil {
		t.Errorf("FileTier().Probe() = %v, want nil", err)
	}
}

func TestUnavailableTier(t *testing.T) {
	tier := unavailableTier(TierDPAPI, "not on this platform")
	if tier.Name != TierDPAPI {
		t.Fatalf("Name = %q, want %q", tier.Name, TierDPAPI)
	}
	p := tier.Open("scope")
	if p.Name() != TierDPAPI {
		t.Fatalf("Open().Name() = %q, want %q", p.Name(), TierDPAPI)
	}
	ops := []struct {
		name string
		err  func() error
	}{
		{"probe", tier.Probe},
		{"wrap", func() error { _, err := p.Wrap(make([]byte, 32)); return err }},
		{"unwrap", func() error { _, err := p.Unwrap([]byte("x")); return err }},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			err := op.err()
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("%s = %v, want errors.Is ErrUnavailable", op.name, err)
			}
			if !strings.Contains(err.Error(), "not on this platform") {
				t.Fatalf("%s = %q, want the reason", op.name, err)
			}
		})
	}
}
