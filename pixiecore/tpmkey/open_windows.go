//go:build windows

package tpmkey

import (
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpm2/transport/windowstpm"
)

// Open opens the system TPM through TBS. path is ignored.
func Open(path string) (transport.TPMCloser, error) {
	return windowstpm.Open()
}
