package cli

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"
	"github.com/wrouesnel/netboot/pixiecore"
	"github.com/wrouesnel/netboot/pixiecore/tpmkey"
	"github.com/wrouesnel/netboot/pixiecore/uefisign"
)

const (
	defaultSecureBootTPMKey = "/var/lib/pixiecore/secureboot.key"
	defaultSecureBootCert   = "/var/lib/pixiecore/secureboot.crt"
)

// secureBootFlags adds the flags that configure Secure Boot signing.
func secureBootFlags(cmd *cobra.Command) {
	cmd.Flags().String("secureboot-key", "", "PEM RSA private key to sign the UEFI iPXE binaries and kernels with, for UEFI Secure Boot")
	cmd.Flags().Bool("secureboot-tpm", false, "Sign the UEFI iPXE binaries and kernels for UEFI Secure Boot with an RSA key in the TPM. Requires --tpm-enabled")
	cmd.Flags().String("secureboot-tpm-key", defaultSecureBootTPMKey, "TSS2 keyfile for --secureboot-tpm, created if it doesn't exist")
	cmd.Flags().String("secureboot-cert", defaultSecureBootCert, "PEM certificate for the Secure Boot signing key, followed by any intermediate certificates up to the certificate in the machines' db")
	tpmDeviceFlags(cmd)
}

// secureBootFromFlags configures s to sign the kernels it serves, and
// signs its UEFI iPXE binaries. It must be called after the iPXE
// binaries are final.
func secureBootFromFlags(cmd *cobra.Command, s *pixiecore.Server) {
	keyFile := mustGetString(cmd, "secureboot-key")
	useTPM, err := cmd.Flags().GetBool("secureboot-tpm")
	if err != nil {
		fatalf("Error reading flag: %s", err)
	}
	certFile := mustGetString(cmd, "secureboot-cert")

	var signer crypto.Signer
	var chain []*x509.Certificate
	switch {
	case keyFile != "" && useTPM:
		fatalf("--secureboot-key and --secureboot-tpm can't be used together")
	case keyFile != "":
		if cmd.Flags().Changed("secureboot-tpm-key") {
			fatalf("--secureboot-tpm-key requires --secureboot-tpm")
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			fatalf("Couldn't load Secure Boot signing key: %s", err)
		}
		var ok bool
		if signer, ok = cert.PrivateKey.(crypto.Signer); !ok {
			fatalf("Secure Boot signing key %q can't sign", keyFile)
		}
		for _, der := range cert.Certificate {
			c, err := x509.ParseCertificate(der)
			if err != nil {
				fatalf("Couldn't parse --secureboot-cert %q: %s", certFile, err)
			}
			chain = append(chain, c)
		}
	case useTPM:
		signer, _ = openTPMKey(cmd, "secureboot-tpm-key", tpmkey.KeyRSA2048, "pixiecore Secure Boot signing key")
		if chain, err = readCertificates(certFile); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				fatalf("Secure Boot certificate %q doesn't exist, create it with \"pixiecore secureboot-cert --tpm-enabled\"", certFile)
			}
			fatalf("Couldn't load Secure Boot certificate: %s", err)
		}
	default:
		for _, name := range []string{"secureboot-cert", "secureboot-tpm-key"} {
			if cmd.Flags().Changed(name) {
				fatalf("--%s requires --secureboot-key or --secureboot-tpm", name)
			}
		}
		return
	}

	s.SecureBootSigner, err = uefisign.New(signer, chain)
	if err != nil {
		fatalf("Secure Boot signing key: %s", err)
	}
	if s.Ipxe, err = signIpxe(s.SecureBootSigner, s.Ipxe); err != nil {
		fatalf("%s", err)
	}
	fmt.Fprintf(os.Stderr, "Signing UEFI iPXE binaries and kernels for Secure Boot as %q\n", chain[0].Subject)
}

// signIpxe returns a copy of the iPXE binaries with the UEFI binaries
// signed. BIOS binaries aren't PE images, and are left as they are.
func signIpxe(signer *uefisign.Signer, ipxe map[pixiecore.Firmware][]byte) (map[pixiecore.Firmware][]byte, error) {
	fwtypes := make([]pixiecore.Firmware, 0, len(ipxe))
	for fwtype := range ipxe {
		fwtypes = append(fwtypes, fwtype)
	}
	sort.Slice(fwtypes, func(i, j int) bool { return fwtypes[i] < fwtypes[j] })

	ret := make(map[pixiecore.Firmware][]byte, len(ipxe))
	for _, fwtype := range fwtypes {
		signed, err := signer.Sign(ipxe[fwtype])
		switch {
		case errors.Is(err, uefisign.ErrNotPE):
			ret[fwtype] = ipxe[fwtype]
		case err != nil:
			return nil, fmt.Errorf("signing the %s iPXE binary: %w", firmwareName(fwtype), err)
		default:
			ret[fwtype] = signed
		}
	}
	return ret, nil
}

var secureBootCertCmd = &cobra.Command{
	Use:   "secureboot-cert",
	Short: "Print the certificate for the TPM-backed Secure Boot signing key",
	Long: `Print the certificate Pixiecore signs UEFI iPXE binaries and kernels
with when run with --secureboot-tpm, so that it can be enrolled in the
db of the machines being booted. This command requires --tpm-enabled.

The RSA private key is created inside the system TPM and never leaves
it. It is stored in --secureboot-tpm-key as a TSS2 keyfile, which is
only usable with this TPM. If the key or certificate don't exist they
are created, and a self-signed certificate is issued for the key.
Running this command again prints the same certificate.

To have the key certified by a CA whose certificate is in the machines'
db instead, use --csr to print a certificate signing request, and save
the signed certificate, followed by any intermediate certificates, to
--secureboot-cert. Pixiecore uses any certificate at --secureboot-cert
that matches the key.

For a key in a file, create the key and certificate with other tools,
e.g. "openssl req -x509 -newkey rsa:2048", and use --secureboot-key.`,
	Args: cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		commonName := mustGetString(cmd, "common-name")
		validity, err := cmd.Flags().GetDuration("validity")
		if err != nil {
			fatalf("Error reading flag: %s", err)
		}
		renew, err := cmd.Flags().GetBool("renew")
		if err != nil {
			fatalf("Error reading flag: %s", err)
		}
		csr, err := cmd.Flags().GetBool("csr")
		if err != nil {
			fatalf("Error reading flag: %s", err)
		}

		signer, _ := openTPMKey(cmd, "secureboot-tpm-key", tpmkey.KeyRSA2048, "pixiecore Secure Boot signing key")
		certPath := mustGetString(cmd, "secureboot-cert")

		if csr {
			if commonName == "" {
				if existing, err := tpmkey.ReadCertificate(certPath); err == nil {
					commonName = existing.Subject.CommonName
				}
			}
			bs, err := tpmkey.CertificateRequest(signer, commonName)
			if err != nil {
				fatalf("%s", err)
			}
			os.Stdout.Write(bs) //nolint:errcheck // Nothing useful to do if stdout fails.
			return
		}

		cert, created, err := tpmkey.LoadOrCreateCertificate(signer, certPath, tpmkey.CertificateOptions{
			CommonName:  commonName,
			Validity:    validity,
			Renew:       renew,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		})
		if err != nil {
			fatalf("Couldn't load Secure Boot certificate: %s", err)
		}
		if created {
			fmt.Fprintf(os.Stderr, "Created self-signed certificate %q\n", certPath)
		}
		os.Stdout.Write(tpmkey.EncodeCertificate(cert)) //nolint:errcheck // Nothing useful to do if stdout fails.
	},
}

func init() {
	rootCmd.AddCommand(secureBootCertCmd)
	tpmDeviceFlags(secureBootCertCmd)
	secureBootCertCmd.Flags().String("secureboot-tpm-key", defaultSecureBootTPMKey, "TSS2 keyfile for the Secure Boot signing key, created if it doesn't exist")
	secureBootCertCmd.Flags().String("secureboot-cert", defaultSecureBootCert, "Certificate for the Secure Boot signing key, created (self-signed) if it doesn't exist")
	secureBootCertCmd.Flags().String("common-name", "", "Subject common name for a new certificate or CSR (default: the existing certificate's, or the hostname)")
	// Firmware doesn't check certificate expiry, so the default is
	// only there to keep the certificate valid for other tools.
	secureBootCertCmd.Flags().Duration("validity", 30*365*24*time.Hour, "Validity period for a new certificate")
	secureBootCertCmd.Flags().Bool("renew", false, "Issue a new self-signed certificate even if one exists")
	secureBootCertCmd.Flags().Bool("csr", false, "Print a certificate signing request for the key instead of a certificate")
}
