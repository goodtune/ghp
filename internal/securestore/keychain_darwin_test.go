//go:build darwin

package securestore

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// securityCall is one recorded invocation of a securityRunner.
type securityCall struct {
	stdin string
	args  []string
}

// securityRecorder is a securityRunner that records its calls and returns
// out and err.
type securityRecorder struct {
	calls []securityCall
	out   []byte
	err   error
}

func (r *securityRecorder) run(_ context.Context, stdin string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, securityCall{stdin: stdin, args: append([]string(nil), args...)})
	return r.out, r.err
}

func testDEK() []byte {
	dek := make([]byte, 32)
	for i := range dek {
		dek[i] = byte(0xa0 + i)
	}
	return dek
}

func TestKeychainProtector_SecretNeverInArgv(t *testing.T) {
	dek := testDEK()
	enc := base64.StdEncoding.EncodeToString(dek)
	account := keychainAccount("/home/u/.config/ghp/git-credential")

	t.Run("wrap", func(t *testing.T) {
		rec := &securityRecorder{}
		p := keychainTier(rec.run).Open("/home/u/.config/ghp/git-credential")
		if p.Name() != TierKeychain {
			t.Fatalf("Name() = %q, want %q", p.Name(), TierKeychain)
		}
		wrapped, err := p.Wrap(dek)
		if err != nil {
			t.Fatalf("Wrap() = %v", err)
		}
		if string(wrapped) != account {
			t.Fatalf("Wrap() = %q, want the account %q", wrapped, account)
		}
		if len(rec.calls) != 1 {
			t.Fatalf("security called %d times, want 1", len(rec.calls))
		}
		c := rec.calls[0]
		if strings.Join(c.args, " ") != "-i" {
			t.Fatalf("args = %q, want [-i]", c.args)
		}
		for _, want := range []string{"add-generic-password -U ", "-s " + KeychainService, "-a " + account, "-w " + enc + "\n"} {
			if !strings.Contains(c.stdin, want) {
				t.Errorf("stdin %q does not contain %q", c.stdin, want)
			}
		}
	})

	t.Run("unwrap", func(t *testing.T) {
		rec := &securityRecorder{out: []byte(enc + "\n")}
		got, err := keychainTier(rec.run).Open("/home/u/.config/ghp/git-credential").Unwrap([]byte(account))
		if err != nil {
			t.Fatalf("Unwrap() = %v", err)
		}
		if !bytes.Equal(got, dek) {
			t.Fatalf("Unwrap() = %x, want %x", got, dek)
		}
		if len(rec.calls) != 1 {
			t.Fatalf("security called %d times, want 1", len(rec.calls))
		}
		want := []string{"find-generic-password", "-s", KeychainService, "-a", account, "-w"}
		if strings.Join(rec.calls[0].args, "\x00") != strings.Join(want, "\x00") {
			t.Fatalf("args = %q, want %q", rec.calls[0].args, want)
		}
		for _, a := range rec.calls[0].args {
			if strings.Contains(a, enc) {
				t.Fatalf("argument %q contains the encoded key", a)
			}
		}
	})
}

func TestKeychainProtector_RejectsBadKey(t *testing.T) {
	tests := []struct {
		name string
		dek  []byte
	}{
		{"short", make([]byte, 16)},
		{"long", make([]byte, 33)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &securityRecorder{}
			if _, err := keychainTier(rec.run).Open("s").Wrap(tt.dek); err == nil {
				t.Fatal("Wrap() = nil error, want an error")
			}
			if len(rec.calls) != 0 {
				t.Fatalf("security called %d times, want 0", len(rec.calls))
			}
		})
	}
}

func TestKeychainProtector_ErrorsCarryNoSecret(t *testing.T) {
	dek := testDEK()
	enc := base64.StdEncoding.EncodeToString(dek)
	rec := &securityRecorder{
		out: []byte(enc),
		err: &securityError{Subcommand: "-i", ExitCode: 45, Stderr: "add-generic-password: returned -25299"},
	}
	_, err := keychainTier(rec.run).Open("s").Wrap(dek)
	if err == nil {
		t.Fatal("Wrap() = nil error, want an error")
	}
	if strings.Contains(err.Error(), enc) {
		t.Fatalf("Wrap() error %q contains the encoded key", err)
	}
	if !strings.Contains(err.Error(), "security -i: exit 45: add-generic-password: returned -25299") {
		t.Fatalf("Wrap() error %q does not carry the security error", err)
	}
}

func TestSecurityError_Error(t *testing.T) {
	err := &securityError{Subcommand: "find-generic-password", ExitCode: 44, Stderr: "not found"}
	if got, want := err.Error(), "security find-generic-password: exit 44: not found"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestSecuritySubcommand(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{[]string{"-i"}, "-i"},
		{nil, "-i"},
		{[]string{"show-keychain-info"}, "show-keychain-info"},
		{[]string{"find-generic-password", "-s", "x"}, "find-generic-password"},
	}
	for _, tt := range tests {
		t.Run(strings.Join(tt.args, " "), func(t *testing.T) {
			if got := securitySubcommand(tt.args); got != tt.want {
				t.Fatalf("securitySubcommand(%q) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}

func TestKeychainProtector_UnwrapErrors(t *testing.T) {
	account := keychainAccount("s")
	tests := []struct {
		name        string
		out         []byte
		err         error
		wantForeign bool
	}{
		{"keychain locked", nil, &securityError{Subcommand: "find-generic-password", ExitCode: 36, Stderr: "User interaction is not allowed."}, false},
		{"runner failure", nil, errors.New("boom"), false},
		{"not base64", []byte("!!!\n"), nil, false},
		{"wrong length", []byte(base64.StdEncoding.EncodeToString(make([]byte, 16)) + "\n"), nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &securityRecorder{out: tt.out, err: tt.err}
			_, err := keychainTier(rec.run).Open("s").Unwrap([]byte(account))
			if err == nil {
				t.Fatal("Unwrap() = nil error, want an error")
			}
			if got := errors.Is(err, ErrForeignKey); got != tt.wantForeign {
				t.Fatalf("Unwrap() = %v; errors.Is ErrForeignKey = %v, want %v", err, got, tt.wantForeign)
			}
		})
	}
}

func TestKeychainProtector_ItemNotFoundIsForeign(t *testing.T) {
	rec := &securityRecorder{err: &securityError{Subcommand: "find-generic-password", ExitCode: 44}}
	_, err := keychainTier(rec.run).Open("s").Unwrap([]byte(keychainAccount("s")))
	if !errors.Is(err, ErrForeignKey) {
		t.Fatalf("Unwrap() = %v, want errors.Is ErrForeignKey", err)
	}
}

func TestKeychainProtector_ProbeUsesShowKeychainInfo(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		rec := &securityRecorder{}
		if err := keychainTier(rec.run).Probe(); err != nil {
			t.Fatalf("Probe() = %v, want nil", err)
		}
		if len(rec.calls) != 1 || len(rec.calls[0].args) != 1 || rec.calls[0].args[0] != "show-keychain-info" {
			t.Fatalf("calls = %+v, want one show-keychain-info call", rec.calls)
		}
		if rec.calls[0].stdin != "" {
			t.Fatalf("stdin = %q, want empty", rec.calls[0].stdin)
		}
	})
	t.Run("locked", func(t *testing.T) {
		rec := &securityRecorder{err: &securityError{Subcommand: "show-keychain-info", ExitCode: 36, Stderr: "User interaction is not allowed."}}
		err := keychainTier(rec.run).Probe()
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Probe() = %v, want errors.Is ErrUnavailable", err)
		}
	})
}

func TestKeychainAccount(t *testing.T) {
	a1 := keychainAccount("/Users/a/.config/ghp/git-credential")
	a2 := keychainAccount("/Users/a/.config/ghp/git-credential")
	b := keychainAccount("/Users/b/.config/ghp/git-credential")
	if a1 != a2 {
		t.Fatalf("same scope gave %q and %q", a1, a2)
	}
	if a1 == b {
		t.Fatalf("different scopes gave the same account %q", a1)
	}
	if !validKeychainAccount(a1) {
		t.Fatalf("account %q is not 64 lower-case hex characters", a1)
	}
	// SHA-256("") is a fixed, well-known value.
	if got, want := keychainAccount(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; got != want {
		t.Fatalf("keychainAccount(\"\") = %q, want %q", got, want)
	}
}

func TestKeychainProtector_UnwrapRejectsBadAccount(t *testing.T) {
	good := keychainAccount("s")
	for _, bad := range []string{
		"x; rm -rf",
		"",
		strings.ToUpper(good),
		good[:63],
		good + "0",
		good[:63] + "g",
	} {
		t.Run(bad, func(t *testing.T) {
			rec := &securityRecorder{}
			if _, err := keychainTier(rec.run).Open("s").Unwrap([]byte(bad)); err == nil {
				t.Fatal("Unwrap() = nil error, want an error")
			}
			if len(rec.calls) != 0 {
				t.Fatalf("security called %d times, want 0", len(rec.calls))
			}
		})
	}
}

// TestRunSecurity_ErrorOmitsStdinAndStdout runs the real /usr/bin/security
// with a script whose first command writes to stdout and whose second fails.
// No keychain item is read or written.
func TestRunSecurity_ErrorOmitsStdinAndStdout(t *testing.T) {
	if _, err := os.Stat(securityPath); err != nil {
		t.Skipf("%s not present: %v", securityPath, err)
	}
	_, err := runSecurity(context.Background(), "help\nbogus-cmd STDIN-MARKER\n", "-i")
	var se *securityError
	if !errors.As(err, &se) {
		t.Fatalf("runSecurity() = %v, want a *securityError", err)
	}
	if se.Subcommand != "-i" || se.ExitCode == 0 {
		t.Fatalf("securityError = %+v, want subcommand -i and a non-zero exit", se)
	}
	msg := err.Error()
	if strings.Contains(msg, "STDIN-MARKER") {
		t.Fatalf("error %q contains the stdin script", msg)
	}
	if strings.Contains(msg, "Show all commands") {
		t.Fatalf("error %q contains stdout", msg)
	}
}

// TestKeychainProtector_RealKeychain wraps and unwraps a key in the real
// default keychain, then deletes the item:
//
//	GHP_TEST_KEYCHAIN=1 go test ./internal/securestore/ -run RealKeychain
func TestKeychainProtector_RealKeychain(t *testing.T) {
	if os.Getenv("GHP_TEST_KEYCHAIN") != "1" {
		t.Skip("GHP_TEST_KEYCHAIN not set to 1; skipping real keychain round trip")
	}
	tier := KeychainTier()
	if err := tier.Probe(); err != nil {
		t.Skipf("keychain unavailable (locked or no default keychain): %v", err)
	}
	scope := "ghp-securestore-test:" + t.Name() + ":" + t.TempDir()
	account := keychainAccount(scope)
	deleteItem := func() error {
		out, err := exec.Command(securityPath, "delete-generic-password", "-s", KeychainService, "-a", account).CombinedOutput()
		if err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) && ee.ExitCode() == 44 {
				return nil // already gone
			}
			return errors.New(strings.TrimSpace(string(out)))
		}
		return nil
	}
	t.Cleanup(func() {
		if err := deleteItem(); err != nil {
			t.Errorf("deleting keychain item %s/%s: %v", KeychainService, account, err)
		}
	})

	p := tier.Open(scope)
	for i, dek := range [][]byte{testDEK(), bytes.Repeat([]byte{0x5a}, 32)} {
		wrapped, err := p.Wrap(dek)
		if err != nil {
			t.Fatalf("Wrap() #%d: %v", i, err)
		}
		got, err := p.Unwrap(wrapped)
		if err != nil {
			t.Fatalf("Unwrap() #%d: %v", i, err)
		}
		if !bytes.Equal(got, dek) {
			t.Fatalf("Unwrap() #%d = %x, want %x", i, got, dek)
		}
	}

	if err := deleteItem(); err != nil {
		t.Fatalf("deleting keychain item: %v", err)
	}
	if _, err := p.Unwrap([]byte(account)); !errors.Is(err, ErrForeignKey) {
		t.Fatalf("Unwrap() after delete = %v, want errors.Is ErrForeignKey", err)
	}
}
