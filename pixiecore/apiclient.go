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

// Headers Pixiecore sends to the API server to identify itself.
const (
	HeaderPixiecoreIP       = "X-Pixiecore-IP"
	HeaderPixiecoreHostname = "X-Pixiecore-Hostname"
	// HeaderPixiecoreProxy is set to "true" when Pixiecore proxies
	// requests from the subnet it manages to the API server.
	HeaderPixiecoreProxy = "X-Pixiecore-Proxy"
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

	// Header holds extra headers to send with every request to the API
	// server, such as HeaderPixiecoreIP. Like basic auth credentials,
	// they are only sent to the API server itself.
	Header http.Header
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
	if cfg.Username != "" || len(cfg.Header) > 0 {
		rt = &apiOriginTransport{
			next:     t,
			scheme:   u.Scheme,
			host:     canonicalHost(u),
			header:   cfg.Header.Clone(),
			username: cfg.Username,
			password: cfg.Password,
		}
	}

	return &http.Client{Transport: rt, Timeout: cfg.Timeout}, nil
}

// apiOriginTransport adds headers and basic auth credentials to
// requests for a single origin.
type apiOriginTransport struct {
	next               http.RoundTripper
	scheme, host       string
	header             http.Header
	username, password string
}

func (b *apiOriginTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme != b.scheme || canonicalHost(req.URL) != b.host {
		return b.next.RoundTrip(req)
	}
	req = req.Clone(req.Context())
	for k, v := range b.header {
		req.Header[k] = v
	}
	if b.username != "" && req.Header.Get("Authorization") == "" {
		req.SetBasicAuth(b.username, b.password)
	}
	return b.next.RoundTrip(req)
}

// DetectLocalIP returns the local IP address the system would use to
// reach the host in apiURL. No packets are sent, but the host is
// resolved if it is a name.
func DetectLocalIP(apiURL string) (net.IP, error) {
	u, err := url.Parse(apiURL)
	if err != nil {
		return nil, fmt.Errorf("invalid API URL %q: %s", apiURL, err)
	}
	conn, err := net.Dial("udp", canonicalHost(u))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("unexpected local address type %T", conn.LocalAddr())
	}
	return addr.IP, nil
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
