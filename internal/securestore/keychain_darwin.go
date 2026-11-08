//go:build darwin

package securestore

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	securityPath    = "/usr/bin/security"
	securityTimeout = 10 * time.Second
	// securityWaitDelay bounds how long Wait blocks after the timeout kills
	// security, should a child process still hold its pipes open.
	securityWaitDelay = time.Second
)

// runSecurity runs the real /usr/bin/security.
var runSecurity securityRunner = execSecurity

func execSecurity(ctx context.Context, stdin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, securityTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, securityPath, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.WaitDelay = securityWaitDelay
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, newSecurityError(ctx, securityTimeout, args, err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// KeychainTier returns the keychain tier backed by the default keychain. Its
// probe also requires /usr/bin/security to exist.
func KeychainTier() Tier {
	t := keychainTier(runSecurity)
	probe := t.Probe
	t.Probe = func() error {
		if _, err := os.Stat(securityPath); err != nil {
			return fmt.Errorf("%w: keychain: %v", ErrUnavailable, err)
		}
		return probe()
	}
	return t
}
