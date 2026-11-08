//go:build windows

package securestore

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// openTPM opens the TPM through the TPM Base Services (TBS).
func openTPM() (transport.TPMCloser, error) { return windowstpm.Open() }
