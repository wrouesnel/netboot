package cli

import (
	"crypto"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/wrouesnel/netboot/pixiecore/tpmkey"
)

var tpmCertCmd = &cobra.Command{
	Use:   "tpm-cert",
	Short: "Print the certificate for the TPM-backed API client key",
	Long: `Print the certificate Pixiecore presents to API servers when run with
--api-client-tpm, so that the API server can be configured to trust it.
This command also requires --tpm-enabled.

The private key is created inside the system TPM and never leaves it. It
is stored in --tpm-key as a TSS2 keyfile, which is only usable with this
TPM. If the key or certificate don't exist they are created, and a
self-signed certificate is issued for the key. Running this command
again prints the same certificate.

To have the key certified by a CA instead, use --csr to print a
certificate signing request, and save the signed certificate to
--tpm-cert. Pixiecore uses any certificate at --tpm-cert that matches
the key.`,
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

		signer, _ := openTPMKey(cmd, "tpm-key", tpmkey.KeyECDSAP256, "pixiecore API client key")
		certPath := mustGetString(cmd, "tpm-cert")

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
			CommonName: commonName,
			Validity:   validity,
			Renew:      renew,
		})
		if err != nil {
			fatalf("Couldn't load TPM client certificate: %s", err)
		}
		if created {
			fmt.Fprintf(os.Stderr, "Created self-signed certificate %q\n", certPath)
		}
		if time.Now().After(cert.NotAfter) {
			fmt.Fprintf(os.Stderr, "WARNING: certificate %q expired at %s, use --renew to issue a new one\n", certPath, cert.NotAfter.Format(time.RFC3339))
		}
		os.Stdout.Write(tpmkey.EncodeCertificate(cert)) //nolint:errcheck // Nothing useful to do if stdout fails.
	},
}

// openTPMKey opens the TPM named by --tpm-device, and loads the key in
// the keyfile named by keyFlag, or creates a keyType key with
// description if it doesn't exist. The TPM is left open for the life of
// the process, since the returned signer uses it.
//
// It is fatal to call this without --tpm-enabled, so the TPM is never
// touched unless explicitly asked for.
func openTPMKey(cmd *cobra.Command, keyFlag string, keyType tpmkey.KeyType, description string) (signer crypto.Signer, keyPath string) {
	enabled, err := tpmEnabled(cmd)
	if err != nil {
		fatalf("%s", err)
	}
	if !enabled {
		fatalf("TPM support is disabled, pass --tpm-enabled to use the TPM")
	}

	device := mustGetString(cmd, "tpm-device")
	keyPath = mustGetString(cmd, keyFlag)
	ownerAuth := []byte(os.Getenv(envTPMOwnerPassword))

	tpm, err := tpmkey.Open(device)
	if err != nil {
		fatalf("%s", err)
	}
	key, created, err := tpmkey.LoadOrCreateKey(tpm, keyPath, ownerAuth, keyType, description)
	if err != nil {
		fatalf("%s", err)
	}
	if created {
		fmt.Fprintf(os.Stderr, "Created TPM key %q\n", keyPath)
	}
	signer, err = tpmkey.Signer(tpm, key, ownerAuth)
	if err != nil {
		fatalf("Couldn't use TPM key %q: %s", keyPath, err)
	}
	return signer, keyPath
}

func init() {
	rootCmd.AddCommand(tpmCertCmd)
	tpmFlags(tpmCertCmd)
	tpmCertCmd.Flags().String("common-name", "", "Subject common name for a new certificate or CSR (default: the existing certificate's, or the hostname)")
	tpmCertCmd.Flags().Duration("validity", 10*365*24*time.Hour, "Validity period for a new certificate")
	tpmCertCmd.Flags().Bool("renew", false, "Issue a new self-signed certificate even if a valid one exists")
	tpmCertCmd.Flags().Bool("csr", false, "Print a certificate signing request for the key instead of a certificate")
}
