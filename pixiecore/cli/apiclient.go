package cli

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/wrouesnel/netboot/pixiecore"
	"github.com/wrouesnel/netboot/pixiecore/tpmkey"
)

const (
	envAPIPassword      = "PIXIECORE_API_PASSWORD"
	envTPMOwnerPassword = "PIXIECORE_TPM_OWNER_PASSWORD"

	defaultTPMKey  = "/var/lib/pixiecore/tpm-client.key"
	defaultTPMCert = "/var/lib/pixiecore/tpm-client.crt"
)

// apiClientFlags adds the flags that configure how Pixiecore connects
// to an API server.
func apiClientFlags(cmd *cobra.Command) {
	cmd.Flags().Duration("api-request-timeout", 5*time.Second, "Timeout for request to the API server")
	cmd.Flags().String("api-ca-cert", "", "PEM file of CA certificates to trust for the API server's certificate (default: system roots)")
	cmd.Flags().Bool("api-insecure", false, "Don't verify the TLS certificates of HTTPS API servers. Insecure, for testing only")
	cmd.Flags().String("api-client-cert", "", "PEM certificate to present to the API server for mTLS")
	cmd.Flags().String("api-client-key", "", "PEM private key for --api-client-cert")
	cmd.Flags().String("api-username", "", "Username for HTTP basic auth to the API server")
	cmd.Flags().String("api-password-file", "", "File containing the password for HTTP basic auth to the API server (or set "+envAPIPassword+")")
	tpmFlags(cmd)
}

// tpmFlags adds the flags that enable and locate the TPM client key.
func tpmFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("tpm-enabled", false, "Use the TPM-resident client key and certificate. Nothing is read from or created in the TPM without this")
	cmd.Flags().String("tpm-device", tpmkey.DefaultDevice, "TPM device, or unix socket of a TPM simulator")
	cmd.Flags().String("tpm-key", defaultTPMKey, "TSS2 keyfile for the TPM client key, created if it doesn't exist")
	cmd.Flags().String("tpm-cert", defaultTPMCert, "Certificate for the TPM client key, created (self-signed) if it doesn't exist")
}

// apiClientFromFlags builds the HTTP client for the API server at
// apiURL.
func apiClientFromFlags(cmd *cobra.Command, apiURL string) *http.Client {
	var cfg pixiecore.APIClientConfig
	var err error

	if cfg.Timeout, err = cmd.Flags().GetDuration("api-request-timeout"); err != nil {
		fatalf("Error reading flag: %s", err)
	}
	caCert := mustGetString(cmd, "api-ca-cert")
	if cfg.InsecureSkipVerify, err = cmd.Flags().GetBool("api-insecure"); err != nil {
		fatalf("Error reading flag: %s", err)
	}
	clientCert := mustGetString(cmd, "api-client-cert")
	clientKey := mustGetString(cmd, "api-client-key")
	useTPM, err := tpmEnabled(cmd)
	if err != nil {
		fatalf("%s", err)
	}
	cfg.Username = mustGetString(cmd, "api-username")
	passwordFile := mustGetString(cmd, "api-password-file")

	if cfg.InsecureSkipVerify && caCert != "" {
		fatalf("--api-insecure can't be used with --api-ca-cert")
	}
	if caCert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(mustFile(caCert)) {
			fatalf("No certificates found in --api-ca-cert %q", caCert)
		}
		cfg.RootCAs = pool
	}

	switch {
	case useTPM && (clientCert != "" || clientKey != ""):
		fatalf("--tpm-enabled can't be used with --api-client-cert/--api-client-key")
	case useTPM:
		cfg.ClientCertificate = tpmCertificateFromFlags(cmd)
	case clientCert != "" || clientKey != "":
		if clientCert == "" || clientKey == "" {
			fatalf("--api-client-cert and --api-client-key must be used together")
		}
		cert, err := tls.LoadX509KeyPair(clientCert, clientKey)
		if err != nil {
			fatalf("Couldn't load API client certificate: %s", err)
		}
		cfg.ClientCertificate = &cert
	}

	switch {
	case passwordFile != "":
		cfg.Password = strings.TrimRight(string(mustFile(passwordFile)), "\r\n")
	default:
		cfg.Password = os.Getenv(envAPIPassword)
	}
	if cfg.Password != "" && cfg.Username == "" {
		fatalf("An API password was given without --api-username")
	}

	if u, err := url.Parse(apiURL); err == nil && u.Scheme == "http" && (cfg.Username != "" || cfg.ClientCertificate != nil) {
		fmt.Fprintf(os.Stderr, "WARNING: API URL %q is not https, credentials will be sent in the clear\n", apiURL)
	}
	if cfg.InsecureSkipVerify {
		fmt.Fprintf(os.Stderr, "WARNING: --api-insecure is set, API server TLS certificates are not verified\n")
	}

	client, err := pixiecore.NewAPIClient(apiURL, cfg)
	if err != nil {
		fatalf("Couldn't create API client: %s", err)
	}
	return client
}

// tpmCertificateFromFlags loads (or creates) the TPM client key and
// certificate.
func tpmCertificateFromFlags(cmd *cobra.Command) *tls.Certificate {
	signer, keyPath := openTPMKey(cmd)
	certPath := mustGetString(cmd, "tpm-cert")

	cert, created, err := tpmkey.LoadOrCreateCertificate(signer, certPath, tpmkey.CertificateOptions{})
	if err != nil {
		fatalf("Couldn't load TPM client certificate: %s", err)
	}
	if created {
		fmt.Fprintf(os.Stderr, "Created self-signed TPM client certificate %q for key %q. Run \"pixiecore tpm-cert\" to print it.\n", certPath, keyPath)
	}
	tlsCert, err := tpmkey.TLSCertificate(cert, signer)
	if err != nil {
		fatalf("TPM client certificate %q: %s (run \"pixiecore tpm-cert --renew\" to issue a new one)", certPath, err)
	}
	return tlsCert
}

// tpmOptionFlags are the flags that only make sense with --tpm-enabled.
var tpmOptionFlags = []string{"tpm-device", "tpm-key", "tpm-cert"}

// tpmEnabled reports whether --tpm-enabled is set. It is an error to
// set any other TPM flag without it, since that would otherwise be
// silently ignored.
func tpmEnabled(cmd *cobra.Command) (bool, error) {
	enabled, err := cmd.Flags().GetBool("tpm-enabled")
	if err != nil {
		return false, fmt.Errorf("error reading flag: %w", err)
	}
	if !enabled {
		for _, name := range tpmOptionFlags {
			if cmd.Flags().Changed(name) {
				return false, fmt.Errorf("--%s requires --tpm-enabled", name)
			}
		}
	}
	return enabled, nil
}

func mustGetString(cmd *cobra.Command, name string) string {
	s, err := cmd.Flags().GetString(name)
	if err != nil {
		fatalf("Error reading flag: %s", err)
	}
	return s
}
