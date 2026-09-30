package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/wrouesnel/netboot/pixiecore"
	"github.com/wrouesnel/netboot/pixiecore/ipxetrust"
	"github.com/wrouesnel/netboot/pixiecore/uefisign"
)

func TestSecureBootFromFlags(t *testing.T) {
	dir := t.TempDir()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pixiecore secure boot"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, "secureboot.crt"), "CERTIFICATE", der)
	writePEM(t, filepath.Join(dir, "secureboot.key"), "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key))
	trust := testServerChain(t, dir)

	cmd := &cobra.Command{}
	serverConfigFlags(cmd)
	if err := cmd.ParseFlags([]string{
		"--secureboot-key", filepath.Join(dir, "secureboot.key"),
		"--secureboot-cert", filepath.Join(dir, "secureboot.crt"),
		"--ipxe-trust-cert", filepath.Join(dir, "ca.crt"),
	}); err != nil {
		t.Fatal(err)
	}
	s := &pixiecore.Server{HTTPPort: 80, Ipxe: builtinIpxe()}
	httpTLSFromFlags(cmd, s)
	secureBootFromFlags(cmd, s)

	if s.SecureBootSigner == nil {
		t.Fatal("kernel signing isn't enabled")
	}
	// The UEFI binaries are signed, after being changed to trust the
	// HTTPS certificate. The BIOS binaries aren't signed.
	builtin := builtinIpxe()
	for fwtype, bs := range s.Ipxe {
		switch fwtype {
		case pixiecore.FirmwareEFI32, pixiecore.FirmwareEFI64, pixiecore.FirmwareEFIBC:
			if ok, err := uefisign.Verify(bs, cert); !ok || err != nil {
				t.Errorf("%s: isn't signed: %v, %v", firmwareName(fwtype), ok, err)
			}
			got, err := ipxetrust.Trusted(bs)
			if want := [][ipxetrust.FingerprintLen]byte{ipxetrust.Fingerprint(trust)}; err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("%s: trusts %x, %v; want %x", firmwareName(fwtype), got, err, want)
			}
		default:
			if !reflect.DeepEqual(bs, builtin[fwtype]) {
				t.Errorf("%s: binary changed", firmwareName(fwtype))
			}
		}
	}
}

func TestSecureBootDisabled(t *testing.T) {
	cmd := &cobra.Command{}
	serverConfigFlags(cmd)
	s := &pixiecore.Server{HTTPPort: 80, Ipxe: builtinIpxe()}
	secureBootFromFlags(cmd, s)
	if s.SecureBootSigner != nil || !reflect.DeepEqual(s.Ipxe, builtinIpxe()) {
		t.Fatal("Secure Boot signing enabled without flags")
	}
}
