//go:build cgo

// The TPM simulator is built from the reference implementation with
// cgo.

package uefisign_test

import (
	"crypto/x509"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/wrouesnel/netboot/pixiecore/tpmkey"
	"github.com/wrouesnel/netboot/pixiecore/uefisign"
)

func TestSignTPM(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("opening TPM simulator: %s", err)
	}
	defer tpm.Close()

	dir := t.TempDir()
	key, _, err := tpmkey.LoadOrCreateKey(tpm, filepath.Join(dir, "secureboot.key"), nil, tpmkey.KeyRSA2048, "test key")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := tpmkey.Signer(tpm, key, nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, _, err := tpmkey.LoadOrCreateCertificate(signer, filepath.Join(dir, "secureboot.crt"), tpmkey.CertificateOptions{
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})
	if err != nil {
		t.Fatal(err)
	}

	s, err := uefisign.New(signer, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := s.Sign(efiImage())
	if err != nil {
		t.Fatalf("Sign: %s", err)
	}
	if ok, err := uefisign.Verify(signed, cert); !ok || err != nil {
		t.Fatalf("TPM signed image doesn't verify: %v, %v", ok, err)
	}
}
