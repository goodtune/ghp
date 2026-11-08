package securestore

// The keychain tier stores the DEK, base64-encoded, as a generic password in
// the default (login) keychain through /usr/bin/security. The wrapped key is
// the item's account name, so the cache file alone does not hold the key.
// The secret goes to `security -i` on stdin and never appears in argv, where
// other local users could read it from the process table.
//
// This file holds the platform-neutral logic so its tests run on every OS;
// keychain_darwin.go wires the real /usr/bin/security runner and
// keychain_other.go reports the tier unavailable elsewhere.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// KeychainService is the service name of every keychain item the tier writes.
const KeychainService = "ghp-git-credential"

// securityItemNotFound is the exit status of security when the item does
// not exist (errSecItemNotFound).
const securityItemNotFound = 44

// securityRunner runs /usr/bin/security with args, feeding stdin, and
// returns its stdout. A failure is a *securityError.
type securityRunner func(ctx context.Context, stdin string, args ...string) ([]byte, error)

// securityError is a failed security run. It carries only the subcommand,
// exit status and stderr: never stdout (which holds the secret on a find) or
// the stdin script (which holds the secret on an add).
type securityError struct {
	Subcommand string
	ExitCode   int
	Stderr     string
}

func (e *securityError) Error() string {
	return fmt.Sprintf("security %s: exit %d: %s", e.Subcommand, e.ExitCode, e.Stderr)
}

// newSecurityError builds the error for a failed run of security with args.
// ctx is the context the command ran under (with its timeout applied), err
// is what Run returned, and stderr is the captured stderr.
func newSecurityError(ctx context.Context, timeout time.Duration, args []string, err error, stderr string) *securityError {
	se := &securityError{Subcommand: securitySubcommand(args), ExitCode: -1, Stderr: strings.TrimSpace(stderr)}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		se.ExitCode = ee.ExitCode()
	}
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		msg := fmt.Sprintf("timed out after %s", timeout)
		if se.Stderr != "" {
			msg += "; " + se.Stderr
		}
		se.Stderr = msg
	case se.Stderr == "":
		// exec and context errors name the program, never its input.
		se.Stderr = err.Error()
	}
	return se
}

// securitySubcommand returns the first non-flag argument, or "-i" for an
// interactive (stdin script) run.
func securitySubcommand(args []string) string {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") {
			return a
		}
	}
	return "-i"
}

// keychainAccount derives the item's account name from the cache directory
// path: 64 lower-case hex characters.
func keychainAccount(scope string) string {
	sum := sha256.Sum256([]byte(scope))
	return hex.EncodeToString(sum[:])
}

// validKeychainAccount reports whether s has the form keychainAccount returns.
func validKeychainAccount(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

type keychainProtector struct {
	account string
	run     securityRunner
}

func (p *keychainProtector) Name() string { return TierKeychain }

// Wrap stores dek in the keychain (replacing any item for the same account)
// and returns the account name.
func (p *keychainProtector) Wrap(dek []byte) ([]byte, error) {
	if len(dek) != 32 {
		return nil, errors.New("keychain: data key must be 32 bytes")
	}
	script := fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n",
		KeychainService, p.account, base64.StdEncoding.EncodeToString(dek))
	if _, err := p.run(context.Background(), script, "-i"); err != nil {
		return nil, fmt.Errorf("keychain: storing data key: %w", err)
	}
	return []byte(p.account), nil
}

// Unwrap reads the DEK stored under the account name wrapped. A missing item
// is ErrForeignKey: the cache was made elsewhere or the item was deleted.
func (p *keychainProtector) Unwrap(wrapped []byte) ([]byte, error) {
	account := string(wrapped)
	if !validKeychainAccount(account) {
		return nil, errors.New("keychain: wrapped key is not a keychain account name")
	}
	out, err := p.run(context.Background(), "", "find-generic-password", "-s", KeychainService, "-a", account, "-w")
	if err != nil {
		var se *securityError
		if errors.As(err, &se) && se.ExitCode == securityItemNotFound {
			return nil, fmt.Errorf("%w: keychain item not found", ErrForeignKey)
		}
		return nil, fmt.Errorf("keychain: reading data key: %w", err)
	}
	dek, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return nil, errors.New("keychain: stored data key is not base64")
	}
	if len(dek) != 32 {
		return nil, fmt.Errorf("keychain: stored data key is %d bytes, want 32", len(dek))
	}
	return dek, nil
}

func keychainTier(run securityRunner) Tier {
	return Tier{
		Name: TierKeychain,
		Probe: func() error {
			// The default keychain; this fails while it is locked.
			if _, err := run(context.Background(), "", "show-keychain-info"); err != nil {
				return fmt.Errorf("%w: keychain: %v", ErrUnavailable, err)
			}
			return nil
		},
		Open: func(scope string) KeyProtector {
			return &keychainProtector{account: keychainAccount(scope), run: run}
		},
	}
}
