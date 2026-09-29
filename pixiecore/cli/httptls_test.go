package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/wrouesnel/netboot/out/ipxe"
	"github.com/wrouesnel/netboot/pixiecore"
	"github.com/wrouesnel/netboot/pixiecore/ipxetrust"
)

// builtinIpxe returns the embedded iPXE binaries, as cmd/pixiecore sets
// them up.
func builtinIpxe() map[pixiecore.Firmware][]byte {
	return map[pixiecore.Firmware][]byte{
		pixiecore.FirmwareX86PC:   ipxe.MustAsset("third_party/ipxe/src/bin/undionly.kpxe"),
		pixiecore.FirmwareEFI32:   ipxe.MustAsset("third_party/ipxe/src/bin-i386-efi/ipxe.efi"),
		pixiecore.FirmwareEFI64:   ipxe.MustAsset("third_party/ipxe/src/bin-x86_64-efi/ipxe.efi"),
		pixiecore.FirmwareEFIBC:   ipxe.MustAsset("third_party/ipxe/src/bin-x86_64-efi/ipxe.efi"),
		pixiecore.FirmwareX86Ipxe: ipxe.MustAsset("third_party/ipxe/src/bin/ipxe.pxe"),
	}
}

// testServerChain writes a server certificate chain (leaf then CA) and
// key to dir, and returns the CA certificate.
func testServerChain(t *testing.T, dir string) *x509.Certificate {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "pixiecore"},
		DNSNames:     []string{"pixiecore.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, "leaf.crt"), "CERTIFICATE", leafDER)
	writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", caDER)
	writePEM(t, filepath.Join(dir, "server.key"), "PRIVATE KEY", keyDER)
	leafPEM, _ := os.ReadFile(filepath.Join(dir, "leaf.crt"))
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err := os.WriteFile(filepath.Join(dir, "server.crt"), append(leafPEM, caPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestHTTPTLSFromFlags(t *testing.T) {
	dir := t.TempDir()
	ca := testServerChain(t, dir)
	extra := testServerChain(t, t.TempDir())
	writePEM(t, filepath.Join(dir, "extra.crt"), "CERTIFICATE", extra.Raw)

	cmd := &cobra.Command{}
	serverConfigFlags(cmd)
	if err := cmd.ParseFlags([]string{
		"--http-tls-cert", filepath.Join(dir, "server.crt"),
		"--http-tls-key", filepath.Join(dir, "server.key"),
		"--https-port", "8443",
		"--http-disabled",
		"--http-host", "pixiecore.example",
		"--ipxe-trust-cert", filepath.Join(dir, "extra.crt"),
	}); err != nil {
		t.Fatal(err)
	}
	s := &pixiecore.Server{HTTPPort: 80, Ipxe: builtinIpxe()}
	httpTLSFromFlags(cmd, s)

	if s.TLSConfig == nil || len(s.TLSConfig.Certificates) != 1 || len(s.TLSConfig.Certificates[0].Certificate) != 2 {
		t.Fatalf("TLS config not set up with the certificate chain: %+v", s.TLSConfig)
	}
	if s.HTTPSPort != 8443 || !s.DisableHTTP || s.HTTPHost != "pixiecore.example" {
		t.Errorf("got HTTPSPort=%d DisableHTTP=%v HTTPHost=%q", s.HTTPSPort, s.DisableHTTP, s.HTTPHost)
	}

	// The UEFI binaries trust the end of the served chain, and the
	// extra certificate. The BIOS binaries are compressed, so can't be
	// changed.
	want := [][ipxetrust.FingerprintLen]byte{ipxetrust.Fingerprint(ca), ipxetrust.Fingerprint(extra)}
	builtin := builtinIpxe()
	for fwtype, bs := range s.Ipxe {
		switch fwtype {
		case pixiecore.FirmwareEFI32, pixiecore.FirmwareEFI64, pixiecore.FirmwareEFIBC:
			got, err := ipxetrust.Trusted(bs)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Errorf("%s: trusts %x, %v; want %x", firmwareNames[fwtype], got, err, want)
			}
			if len(bs) != len(builtin[fwtype]) {
				t.Errorf("%s: size changed from %d to %d", firmwareNames[fwtype], len(builtin[fwtype]), len(bs))
			}
		default:
			if !reflect.DeepEqual(bs, builtin[fwtype]) {
				t.Errorf("%s: binary changed", firmwareNames[fwtype])
			}
		}
	}
}

func TestBuiltinIpxeTrust(t *testing.T) {
	// The embedded UEFI binaries have a patchable table, which trusts
	// the iPXE root CA unless built with MAGE_IPXE_TRUST.
	for _, fwtype := range []pixiecore.Firmware{pixiecore.FirmwareEFI32, pixiecore.FirmwareEFI64} {
		got, err := ipxetrust.Trusted(builtinIpxe()[fwtype])
		if err != nil || len(got) == 0 {
			t.Errorf("%s: trusts %x, %v", firmwareNames[fwtype], got, err)
		}
	}
}
