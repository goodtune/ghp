package securestore

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
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
		wantScript := "add-generic-password -U -s ghp-git-credential -a " + account + " -w " + enc + "\n"
		if c.stdin != wantScript {
			t.Fatalf("stdin = %q, want %q", c.stdin, wantScript)
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
		{"not base64", []byte("!!!\n"), nil, true},
		{"wrong length", []byte(base64.StdEncoding.EncodeToString(make([]byte, 16)) + "\n"), nil, true},
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
			if errors.Is(err, ErrUnavailable) {
				t.Fatalf("Unwrap() = %v, must not be ErrUnavailable", err)
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

func TestNewSecurityError(t *testing.T) {
	expired, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	tests := []struct {
		name   string
		ctx    context.Context
		args   []string
		err    error
		stderr string
		want   string
	}{
		{"stderr", context.Background(), []string{"find-generic-password", "-s", "x"}, errors.New("exit status 44"),
			"  not found\n", "security find-generic-password: exit -1: not found"},
		{"no stderr", context.Background(), []string{"-i"}, errors.New("fork/exec /usr/bin/security: no such file or directory"),
			"", "security -i: exit -1: fork/exec /usr/bin/security: no such file or directory"},
		{"timeout", expired, []string{"show-keychain-info"}, errors.New("signal: killed"),
			"", "security show-keychain-info: exit -1: timed out after 10s"},
		{"timeout with stderr", expired, []string{"show-keychain-info"}, errors.New("signal: killed"),
			"partial\n", "security show-keychain-info: exit -1: timed out after 10s; partial"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := newSecurityError(tt.ctx, 10*time.Second, tt.args, tt.err, tt.stderr)
			if got.Error() != tt.want {
				t.Fatalf("Error() = %q, want %q", got.Error(), tt.want)
			}
		})
	}
}
