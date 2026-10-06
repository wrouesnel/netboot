package cli

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
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
	cmd.Flags().Bool("api-client-tpm", false, "Present a client certificate whose key is held in the TPM (--tpm-key, --tpm-cert) to the API server for mTLS. Requires --tpm-enabled")
	cmd.Flags().String("api-username", "", "Username for HTTP basic auth to the API server")
	cmd.Flags().String("api-password-file", "", "File containing the password for HTTP basic auth to the API server (or set "+envAPIPassword+")")
	cmd.Flags().String("api-pixiecore-ip", "", "IP address sent to the API server in the "+pixiecore.HeaderPixiecoreIP+" header (default: --listen-addr if set, else the local address used to reach the API server)")
	cmd.Flags().StringArray("api-header", nil, "Extra header to send to the API server, as \"Name: value\". Can be repeated")
	cmd.Flags().String("api-pixiecore-hostname", "", "Hostname sent to the API server in the "+pixiecore.HeaderPixiecoreHostname+" header (default: the system hostname)")
	tpmFlags(cmd)
}

// tpmFlags adds the flags that enable the TPM and locate the TPM client
// key.
func tpmFlags(cmd *cobra.Command) {
	tpmDeviceFlags(cmd)
	if cmd.Flags().Lookup("tpm-key") != nil {
		// Already added, by the API client or Secure Boot flags.
		return
	}
	cmd.Flags().String("tpm-key", defaultTPMKey, "TSS2 keyfile for the TPM client key, created if it doesn't exist")
	cmd.Flags().String("tpm-cert", defaultTPMCert, "Certificate for the TPM client key, created (self-signed) if it doesn't exist")
}

// tpmDeviceFlags adds the flags that enable and locate the TPM, unless
// cmd already has them.
func tpmDeviceFlags(cmd *cobra.Command) {
	if cmd.Flags().Lookup("tpm-enabled") != nil {
		return
	}
	cmd.Flags().Bool("tpm-enabled", false, "Allow Pixiecore to use the TPM, for --api-client-tpm and --secureboot-tpm. Nothing is read from or created in the TPM without this")
	cmd.Flags().String("tpm-device", tpmkey.DefaultDevice, "TPM device, or unix socket of a TPM simulator")
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
	useTPM, err := apiClientTPM(cmd)
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
		fatalf("--api-client-tpm can't be used with --api-client-cert/--api-client-key")
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

	if cfg.Header, err = identityHeaders(cmd, apiURL); err != nil {
		fatalf("%s", err)
	}
	if err := customHeaders(cmd, "api-header", cfg.Header); err != nil {
		fatalf("%s", err)
	}
	if cfg.Username != "" && cfg.Header.Get("Authorization") != "" {
		fatalf("--api-username can't be used with an Authorization --api-header")
	}

	if u, err := url.Parse(apiURL); err == nil && u.Scheme == "http" && (cfg.Username != "" || cfg.ClientCertificate != nil || cfg.Header.Get("Authorization") != "") {
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

// identityHeaders returns the headers that tell the API server which
// Pixiecore instance a request came from. Values not set by flags are
// detected.
func identityHeaders(cmd *cobra.Command, apiURL string) (http.Header, error) {
	ip, err := pixiecoreIP(cmd, apiURL)
	if err != nil {
		return nil, err
	}
	// Commands without API flags (e.g. boot, for a Secure Boot signing
	// service) use the defaults.
	hostname := optionalString(cmd, "api-pixiecore-hostname")

	if hostname == "" {
		var err error
		if hostname, err = os.Hostname(); err != nil {
			return nil, fmt.Errorf("couldn't get the hostname, set --api-pixiecore-hostname: %w", err)
		}
	}

	h := http.Header{}
	h.Set(pixiecore.HeaderPixiecoreIP, ip.String())
	h.Set(pixiecore.HeaderPixiecoreHostname, hostname)
	// Commands without Pixiecore's server (ipv6api) don't have these
	// flags, and send no ports.
	if cmd.Flags().Lookup("dns") != nil {
		enabled, err := cmd.Flags().GetBool("dns")
		if err != nil {
			return nil, fmt.Errorf("error reading flag: %w", err)
		}
		port, err := cmd.Flags().GetInt("dns-port")
		if err != nil {
			return nil, fmt.Errorf("error reading flag: %w", err)
		}
		if enabled {
			h.Set(pixiecore.HeaderPixiecoreDNS, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
		}
	}
	if cmd.Flags().Lookup("http-proxy") != nil {
		proxy, err := cmd.Flags().GetBool("http-proxy")
		if err != nil {
			return nil, fmt.Errorf("error reading flag: %w", err)
		}
		port, err := cmd.Flags().GetInt("http-proxy-port")
		if err != nil {
			return nil, fmt.Errorf("error reading flag: %w", err)
		}
		if proxy {
			h.Set(pixiecore.HeaderPixiecoreProxyPort, strconv.Itoa(port))
		}
	}
	if f := cmd.Flags().Lookup("port"); f != nil {
		disabled, err := cmd.Flags().GetBool("http-disabled")
		if err != nil {
			return nil, fmt.Errorf("error reading flag: %w", err)
		}
		if !disabled {
			h.Set(pixiecore.HeaderPixiecoreHTTPPort, f.Value.String())
		}
	}
	if f := cmd.Flags().Lookup("https-port"); f != nil && mustGetString(cmd, "http-tls-cert") != "" {
		h.Set(pixiecore.HeaderPixiecoreHTTPSPort, f.Value.String())
	}
	return h, nil
}

// pixiecoreIP returns Pixiecore's IP address, as sent to the API
// server: --api-pixiecore-ip, else --listen-addr if it's a specific
// address, else the local address used to reach apiURL.
func pixiecoreIP(cmd *cobra.Command, apiURL string) (net.IP, error) {
	if s := optionalString(cmd, "api-pixiecore-ip"); s != "" {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("--api-pixiecore-ip %q is not an IP address", s)
		}
		return ip, nil
	}
	// Prefer the address Pixiecore is serving on, since that's the
	// address machines will boot from.
	if f := cmd.Flags().Lookup("listen-addr"); f != nil {
		if ip := net.ParseIP(f.Value.String()); ip != nil && !ip.IsUnspecified() {
			return ip, nil
		}
	}
	ip, err := pixiecore.DetectLocalIP(apiURL)
	if err != nil {
		hint := "set --listen-addr to a specific address"
		if cmd.Flags().Lookup("api-pixiecore-ip") != nil {
			hint = "set --api-pixiecore-ip"
		}
		return nil, fmt.Errorf("couldn't detect the local IP address used to reach %s, %s: %w", apiURL, hint, err)
	}
	return ip, nil
}

// customHeaders adds the headers given in flag, a string array of
// "Name: value" headers such as --api-header, to h.
func customHeaders(cmd *cobra.Command, flag string, h http.Header) error {
	headers, err := cmd.Flags().GetStringArray(flag)
	if err != nil {
		return fmt.Errorf("error reading flag: %w", err)
	}
	for _, header := range headers {
		name, value, ok := strings.Cut(header, ":")
		if !ok || !validHeaderName(name) {
			return fmt.Errorf("--%s %q isn't of the form \"Name: value\"", flag, header)
		}
		value = strings.TrimSpace(value)
		if !validHeaderValue(value) {
			return fmt.Errorf("--%s %q: the value can't contain line breaks or control characters", flag, header)
		}
		name = http.CanonicalHeaderKey(name)
		if strings.HasPrefix(name, "X-Pixiecore-") || name == "Host" {
			return fmt.Errorf("--%s %q: %s is set by Pixiecore", flag, header, name)
		}
		h.Add(name, value)
	}
	return nil
}

// validHeaderValue reports whether value can be sent as an HTTP header
// value: no control characters other than tab.
func validHeaderValue(value string) bool {
	for _, c := range []byte(value) {
		if (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

// validHeaderName reports whether name is an HTTP token (RFC 9110).
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range []byte(name) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// tpmCertificateFromFlags loads (or creates) the TPM client key and
// certificate.
func tpmCertificateFromFlags(cmd *cobra.Command) *tls.Certificate {
	signer, keyPath := openTPMKey(cmd, "tpm-key", tpmkey.KeyECDSAP256, "pixiecore API client key")
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

// apiClientTPM reports whether --api-client-tpm is set, checking that
// the TPM is enabled for it, and that the TPM client key flags aren't
// set without it.
func apiClientTPM(cmd *cobra.Command) (bool, error) {
	enabled, err := tpmEnabled(cmd)
	if err != nil {
		return false, err
	}
	useTPM, err := cmd.Flags().GetBool("api-client-tpm")
	if err != nil {
		return false, fmt.Errorf("error reading flag: %w", err)
	}
	if useTPM && !enabled {
		return false, errors.New("--api-client-tpm requires --tpm-enabled")
	}
	if err := checkTPMClientFlags(cmd); err != nil {
		return false, err
	}
	return useTPM, nil
}

// tpmClientUsers are the flags that use the TPM client key and
// certificate (--tpm-key, --tpm-cert).
var tpmClientUsers = []string{"api-client-tpm", "secureboot-delegate-client-tpm"}

// checkTPMClientFlags checks that --tpm-key and --tpm-cert are only
// given when something uses them.
func checkTPMClientFlags(cmd *cobra.Command) error {
	var users []string
	for _, name := range tpmClientUsers {
		if cmd.Flags().Lookup(name) == nil {
			continue
		}
		used, err := cmd.Flags().GetBool(name)
		if err != nil {
			return fmt.Errorf("error reading flag: %w", err)
		}
		if used {
			return nil
		}
		users = append(users, "--"+name)
	}
	for _, name := range []string{"tpm-key", "tpm-cert"} {
		if cmd.Flags().Changed(name) {
			return fmt.Errorf("--%s requires %s", name, strings.Join(users, " or "))
		}
	}
	return nil
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

// optionalString returns the value of flag name, or "" if cmd doesn't
// have it.
func optionalString(cmd *cobra.Command, name string) string {
	if cmd.Flags().Lookup(name) == nil {
		return ""
	}
	return mustGetString(cmd, name)
}

func mustGetString(cmd *cobra.Command, name string) string {
	s, err := cmd.Flags().GetString(name)
	if err != nil {
		fatalf("Error reading flag: %s", err)
	}
	return s
}
