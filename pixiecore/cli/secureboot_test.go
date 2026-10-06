package cli

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
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

func TestSecureBootDelegateFromFlags(t *testing.T) {
	dir := t.TempDir()
	testServerChain(t, dir)

	cmd := &cobra.Command{}
	serverConfigFlags(cmd)
	if err := cmd.ParseFlags([]string{
		"--secureboot-delegate-url", "https://signer.example/sign",
		"--secureboot-delegate-ca-cert", filepath.Join(dir, "ca.crt"),
		"--secureboot-delegate-client-cert", filepath.Join(dir, "server.crt"),
		"--secureboot-delegate-client-key", filepath.Join(dir, "server.key"),
		"--secureboot-delegate-timeout", "5s",
	}); err != nil {
		t.Fatal(err)
	}
	s := &pixiecore.Server{HTTPPort: 80, Ipxe: builtinIpxe()}
	secureBootFromFlags(cmd, s)

	if s.SecureBootSigner != nil || s.SecureBootDelegate == nil {
		t.Fatalf("got signer %v, delegate %v; want only a delegate", s.SecureBootSigner, s.SecureBootDelegate)
	}
	if s.SecureBootDelegate.URL != "https://signer.example/sign" || s.SecureBootDelegate.Client.Timeout != 5*time.Second {
		t.Errorf("delegate has URL %q, timeout %s", s.SecureBootDelegate.URL, s.SecureBootDelegate.Client.Timeout)
	}
	// The iPXE binaries are signed per machine when they're served.
	if !reflect.DeepEqual(s.Ipxe, builtinIpxe()) {
		t.Error("iPXE binaries were changed at startup")
	}
}

// envFatalArgs, in a child test process, holds the flags for
// TestSecureBootDelegateFlagErrors to run secureBootFromFlags with.
const envFatalArgs = "PIXIECORE_TEST_SECUREBOOT_ARGS"

func TestSecureBootDelegateFlagErrors(t *testing.T) {
	if env := os.Getenv(envFatalArgs); env != "" {
		var args []string
		if err := json.Unmarshal([]byte(env), &args); err != nil {
			t.Fatal(err)
		}
		cmd := &cobra.Command{}
		serverConfigFlags(cmd)
		if err := cmd.ParseFlags(args); err != nil {
			t.Fatal(err)
		}
		secureBootFromFlags(cmd, &pixiecore.Server{Ipxe: builtinIpxe()})
		os.Exit(0)
	}

	dir := t.TempDir()
	testServerChain(t, dir)
	cert, key := filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key")
	url := "https://signer.example/sign"
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--secureboot-delegate-url", "http://signer.example/sign"}, "must be an https:// URL"},
		{[]string{"--secureboot-delegate-url", "signer.example"}, "must be an https:// URL"},
		{[]string{"--secureboot-delegate-url", url, "--secureboot-key", key}, "can't be used with --secureboot-key or --secureboot-tpm"},
		{[]string{"--secureboot-delegate-url", url, "--tpm-enabled", "--secureboot-tpm"}, "can't be used with --secureboot-key or --secureboot-tpm"},
		{[]string{"--secureboot-delegate-url", url, "--secureboot-cert", cert}, "is for local signing"},
		{[]string{"--secureboot-delegate-client-cert", cert, "--secureboot-delegate-client-key", key}, "requires --secureboot-delegate-url"},
		{[]string{"--secureboot-key", key, "--secureboot-cert", cert, "--secureboot-delegate-timeout", "5s"}, "requires --secureboot-delegate-url"},
		{[]string{"--secureboot-delegate-url", url, "--secureboot-delegate-client-cert", cert}, "must be used together"},
		{[]string{"--secureboot-delegate-url", url, "--secureboot-delegate-client-tpm"}, "requires --tpm-enabled"},
		{[]string{"--secureboot-delegate-url", url, "--tpm-enabled", "--secureboot-delegate-client-tpm", "--secureboot-delegate-client-cert", cert, "--secureboot-delegate-client-key", key}, "can't be used with --secureboot-delegate-client-cert"},
		{[]string{"--secureboot-delegate-url", url, "--secureboot-delegate-timeout", "0s"}, "must be positive"},
		{[]string{"--secureboot-delegate-url", url, "--secureboot-delegate-ca-cert", key}, "No certificates found"},
		{[]string{"--secureboot-delegate-url", url, "--tpm-key", filepath.Join(dir, "tpm.key")}, "--tpm-key requires --secureboot-delegate-client-tpm"},
	}
	for _, tc := range cases {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSecureBootDelegateFlagErrors$")
		args, _ := json.Marshal(tc.args)
		cmd.Env = append(os.Environ(), envFatalArgs+"="+string(args))
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || !strings.Contains(string(out), tc.want) {
			t.Errorf("%q: got %v, output %q; want exit 1 with %q", tc.args, err, out, tc.want)
		}
	}
}
