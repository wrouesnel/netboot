package pixiecore

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// APIClientConfig configures the HTTP client used to talk to a
// Pixiecore API server.
type APIClientConfig struct {
	// Timeout for requests to the API server. Zero means no timeout.
	Timeout time.Duration

	// RootCAs is the set of CAs trusted to sign the API server's
	// certificate. If nil, the system roots are used.
	RootCAs *x509.CertPool
	// InsecureSkipVerify disables verification of server certificates,
	// so any server can impersonate the API server. For testing only.
	InsecureSkipVerify bool
	// ClientCertificate is presented to the API server for mTLS
	// authentication, if the server asks for one.
	ClientCertificate *tls.Certificate

	// Username and Password, if Username is set, are sent as HTTP
	// basic auth credentials. They are only sent to the API server
	// itself (same scheme, host and port as the API URL), not to other
	// servers that boot files are fetched from.
	Username string
	Password string
}

// NewAPIClient returns an HTTP client for the API server at apiURL.
func NewAPIClient(apiURL string, cfg APIClientConfig) (*http.Client, error) {
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, fmt.Errorf("invalid API URL %q: %s", apiURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("invalid API URL %q: scheme must be http or https", apiURL)
	}

	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("http.DefaultTransport is not an *http.Transport")
	}
	t := base.Clone()
	t.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		RootCAs:            cfg.RootCAs,
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // Explicitly requested with --api-insecure.
	}
	if cfg.ClientCertificate != nil {
		cert := cfg.ClientCertificate
		t.TLSClientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert, nil
		}
	}

	var rt http.RoundTripper = t
	if cfg.Username != "" {
		rt = &basicAuthTransport{
			next:     t,
			scheme:   u.Scheme,
			host:     canonicalHost(u),
			username: cfg.Username,
			password: cfg.Password,
		}
	}

	return &http.Client{Transport: rt, Timeout: cfg.Timeout}, nil
}

// basicAuthTransport adds basic auth credentials to requests for a
// single origin.
type basicAuthTransport struct {
	next               http.RoundTripper
	scheme, host       string
	username, password string
}

func (b *basicAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != b.scheme || canonicalHost(req.URL) != b.host || req.Header.Get("Authorization") != "" {
		return b.next.RoundTrip(req)
	}
	req = req.Clone(req.Context())
	req.SetBasicAuth(b.username, b.password)
	return b.next.RoundTrip(req)
}

// canonicalHost returns u's host:port, with the default port filled in.
func canonicalHost(u *url.URL) string {
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}
