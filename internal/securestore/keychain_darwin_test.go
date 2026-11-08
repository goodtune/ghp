//go:build darwin

package securestore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

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
