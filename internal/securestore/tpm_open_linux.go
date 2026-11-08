//go:build linux

package securestore

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
)

// openTPM prefers the kernel resource manager; /dev/tpm0 is exclusive-open and usually root/tss only.
func openTPM() (transport.TPMCloser, error) {
	if t, err := linuxtpm.Open("/dev/tpmrm0"); err == nil {
		return t, nil
	}
	return linuxtpm.Open("/dev/tpm0")
}
