//go:build !windows

package tpmkey

import (
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/linuxtpm"
	"github.com/google/go-tpm/tpm2/transport/linuxudstpm"
)

// Open opens the TPM at path. A character device is opened directly;
// a unix socket is treated as a TPM simulator such as swtpm.
func Open(path string) (transport.TPMCloser, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("opening TPM: %w", err)
	}
	if fi.Mode()&os.ModeSocket != 0 {
		return linuxudstpm.Open(path)
	}
	return linuxtpm.Open(path)
}
