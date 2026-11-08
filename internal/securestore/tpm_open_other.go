//go:build !linux && !windows

package securestore

import (
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
)

// openTPM reports the tier unavailable: this platform has no TPM transport.
func openTPM() (transport.TPMCloser, error) {
	return nil, fmt.Errorf("%w: no TPM transport on this platform", ErrUnavailable)
}
