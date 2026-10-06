package cli

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/wrouesnel/netboot/pixiecore"
)

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAPIClientFromFlags(t *testing.T) {
	dir := t.TempDir()

	// Self-signed client certificate and key files.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pixiecore-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	clientCert, _ := x509.ParseCertificate(der)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, "client.crt"), "CERTIFICATE", der)
	writePEM(t, filepath.Join(dir, "client.key"), "PRIVATE KEY", keyDER)
	if err := os.WriteFile(filepath.Join(dir, "password"), []byte("s3cret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(clientCert)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, ok := r.BasicAuth(); !ok || u != "pxe" || p != "s3cret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_, _ = io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}
	srv.StartTLS()
	defer srv.Close()
	writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", srv.Certificate().Raw)

	cmd := &cobra.Command{}
	apiClientFlags(cmd)
	if err := cmd.ParseFlags([]string{
		"--api-ca-cert", filepath.Join(dir, "ca.crt"),
		"--api-client-cert", filepath.Join(dir, "client.crt"),
		"--api-client-key", filepath.Join(dir, "client.key"),
		"--api-username", "pxe",
		"--api-password-file", filepath.Join(dir, "password"),
	}); err != nil {
		t.Fatal(err)
	}

	client := apiClientFromFlags(cmd, srv.URL)
	resp, err := client.Get(srv.URL + "/v1/boot/01:02:03:04:05:06")
	if err != nil {
		t.Fatalf("request: %s", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "pixiecore-test" {
		t.Fatalf("got %s %q", resp.Status, body)
	}
}

func TestTPMEnabled(t *testing.T) {
	cases := []struct {
		args    []string
		want    bool
		wantErr bool
	}{
		{args: nil, want: false},
		{args: []string{"--tpm-enabled"}, want: true},
		{args: []string{"--tpm-enabled", "--tpm-key", "/k", "--tpm-cert", "/c", "--tpm-device", "/d"}, want: true},
		{args: []string{"--tpm-key", "/k"}, wantErr: true},
		{args: []string{"--tpm-cert", "/c"}, wantErr: true},
		{args: []string{"--tpm-device", "/d"}, wantErr: true},
		{args: []string{"--tpm-enabled=false", "--tpm-key", "/k"}, wantErr: true},
	}
	for _, tc := range cases {
		cmd := &cobra.Command{}
		apiClientFlags(cmd)
		if err := cmd.ParseFlags(tc.args); err != nil {
			t.Fatal(err)
		}
		got, err := tpmEnabled(cmd)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("tpmEnabled(%q) = %v, %v; want %v, error=%v", tc.args, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestAPIClientTPM(t *testing.T) {
	cases := []struct {
		args    []string
		want    bool
		wantErr bool
	}{
		{args: nil, want: false},
		// The TPM can be enabled for other uses, e.g. Secure Boot
		// signing, without presenting the TPM client certificate.
		{args: []string{"--tpm-enabled"}, want: false},
		{args: []string{"--tpm-enabled", "--api-client-tpm"}, want: true},
		{args: []string{"--tpm-enabled", "--api-client-tpm", "--tpm-key", "/k", "--tpm-cert", "/c"}, want: true},
		{args: []string{"--api-client-tpm"}, wantErr: true},
		{args: []string{"--tpm-enabled", "--tpm-key", "/k"}, wantErr: true},
		{args: []string{"--tpm-enabled", "--tpm-cert", "/c"}, wantErr: true},
	}
	for _, tc := range cases {
		cmd := &cobra.Command{}
		serverConfigFlags(cmd)
		apiClientFlags(cmd)
		if err := cmd.ParseFlags(tc.args); err != nil {
			t.Fatal(err)
		}
		got, err := apiClientTPM(cmd)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("apiClientTPM(%q) = %v, %v; want %v, error=%v", tc.args, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestIdentityHeaders(t *testing.T) {
	hostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		args         []string
		wantIP       string
		wantHostname string
		wantErr      bool
	}{
		// The loopback API server is reached from the loopback address.
		{args: nil, wantIP: "127.0.0.1", wantHostname: hostname},
		{args: []string{"--listen-addr", "0.0.0.0"}, wantIP: "127.0.0.1", wantHostname: hostname},
		{args: []string{"--listen-addr", "192.0.2.1"}, wantIP: "192.0.2.1", wantHostname: hostname},
		{
			args:         []string{"--listen-addr", "192.0.2.1", "--api-pixiecore-ip", "2001:db8::1", "--api-pixiecore-hostname", "pxe1"},
			wantIP:       "2001:db8::1",
			wantHostname: "pxe1",
		},
		{args: []string{"--api-pixiecore-ip", "not-an-ip"}, wantErr: true},
	}
	for _, tc := range cases {
		cmd := &cobra.Command{}
		cmd.Flags().String("listen-addr", "", "")
		apiClientFlags(cmd)
		if err := cmd.ParseFlags(tc.args); err != nil {
			t.Fatal(err)
		}
		h, err := identityHeaders(cmd, "http://127.0.0.1:8080")
		if tc.wantErr {
			if err == nil {
				t.Errorf("identityHeaders(%q): want error", tc.args)
			}
			continue
		}
		if err != nil {
			t.Fatalf("identityHeaders(%q): %s", tc.args, err)
		}
		if got := h.Get(pixiecore.HeaderPixiecoreIP); got != tc.wantIP {
			t.Errorf("identityHeaders(%q): IP %q, want %q", tc.args, got, tc.wantIP)
		}
		if got := h.Get(pixiecore.HeaderPixiecoreHostname); got != tc.wantHostname {
			t.Errorf("identityHeaders(%q): hostname %q, want %q", tc.args, got, tc.wantHostname)
		}
		// Without Pixiecore's server flags, no ports are sent.
		for _, name := range []string{pixiecore.HeaderPixiecoreHTTPPort, pixiecore.HeaderPixiecoreHTTPSPort, pixiecore.HeaderPixiecoreProxyPort, pixiecore.HeaderPixiecoreDNS} {
			if _, ok := h[name]; ok {
				t.Errorf("identityHeaders(%q): unexpected %s header", tc.args, name)
			}
		}
	}
}

func TestIdentityHeadersPorts(t *testing.T) {
	cases := []struct {
		args          []string
		wantHTTPPort  string
		wantHTTPSPort string
		wantProxyPort string
		wantDNS       string
		wantErr       bool
	}{
		{args: []string{"--http-proxy"}, wantHTTPPort: "80", wantProxyPort: "3128"},
		{args: []string{"--http-proxy", "--http-proxy-port", "8081"}, wantHTTPPort: "80", wantProxyPort: "8081"},
		{args: []string{"--http-proxy-port", "8081"}, wantHTTPPort: "80"},
		{args: []string{"--dns"}, wantHTTPPort: "80", wantDNS: "192.0.2.1:53"},
		{args: []string{"--dns", "--dns-port", "5353"}, wantHTTPPort: "80", wantDNS: "192.0.2.1:5353"},
		{args: []string{"--dns", "--api-pixiecore-ip", "2001:db8::1"}, wantHTTPPort: "80", wantDNS: "[2001:db8::1]:53"},
		{args: nil, wantHTTPPort: "80"},
		{args: []string{"--port", "8080"}, wantHTTPPort: "8080"},
		{args: []string{"--http-tls-cert", "server.crt"}, wantHTTPPort: "80", wantHTTPSPort: "443"},
		{args: []string{"--port", "8080", "--http-tls-cert", "server.crt", "--https-port", "8443"}, wantHTTPPort: "8080", wantHTTPSPort: "8443"},
		{args: []string{"--http-tls-cert", "server.crt", "--https-port", "8443", "--http-disabled"}, wantHTTPSPort: "8443"},
	}
	for _, tc := range cases {
		cmd := &cobra.Command{}
		serverConfigFlags(cmd)
		apiClientFlags(cmd)
		cmd.Flags().Bool("http-proxy", false, "")
		cmd.Flags().Int("http-proxy-port", 3128, "")
		dnsFlags(cmd)
		if err := cmd.ParseFlags(append([]string{"--api-pixiecore-ip", "192.0.2.1"}, tc.args...)); err != nil {
			t.Fatal(err)
		}
		h, err := identityHeaders(cmd, "http://127.0.0.1:8080")
		if tc.wantErr {
			if err == nil {
				t.Errorf("identityHeaders(%q): want error", tc.args)
			}
			continue
		}
		if err != nil {
			t.Fatalf("identityHeaders(%q): %s", tc.args, err)
		}
		for name, want := range map[string]string{
			pixiecore.HeaderPixiecoreHTTPPort:  tc.wantHTTPPort,
			pixiecore.HeaderPixiecoreHTTPSPort: tc.wantHTTPSPort,
			pixiecore.HeaderPixiecoreProxyPort: tc.wantProxyPort,
			pixiecore.HeaderPixiecoreDNS:       tc.wantDNS,
		} {
			got, ok := h[http.CanonicalHeaderKey(name)]
			if want == "" {
				if ok {
					t.Errorf("identityHeaders(%q): %s is %q, want it absent", tc.args, name, got)
				}
			} else if !ok || len(got) != 1 || got[0] != want {
				t.Errorf("identityHeaders(%q): %s is %q, want %q", tc.args, name, got, want)
			}
		}
	}
}

func TestCustomHeaders(t *testing.T) {
	cases := []struct {
		args    []string
		want    http.Header
		wantErr bool
	}{
		{args: nil, want: http.Header{}},
		{
			args: []string{"--api-header", "X-Site: syd1", "--api-header", "authorization:Bearer abc"},
			want: http.Header{"X-Site": {"syd1"}, "Authorization": {"Bearer abc"}},
		},
		// Values can have commas and colons, and names can repeat.
		{
			args: []string{"--api-header", "X-Tags: a, b", "--api-header", "X-Tags: c:d", "--api-header", "X-Empty:"},
			want: http.Header{"X-Tags": {"a, b", "c:d"}, "X-Empty": {""}},
		},
		{args: []string{"--api-header", "X-Site"}, wantErr: true},
		{args: []string{"--api-header", ": value"}, wantErr: true},
		{args: []string{"--api-header", "X Site: syd1"}, wantErr: true},
		{args: []string{"--api-header", "X-Site: a\r\nX-Other: b"}, wantErr: true},
		{args: []string{"--api-header", "X-Pixiecore-IP: 192.0.2.1"}, wantErr: true},
		{args: []string{"--api-header", "x-pixiecore-proxy-port: 1"}, wantErr: true},
		{args: []string{"--api-header", "Host: example"}, wantErr: true},
		{args: []string{"--api-header", "X-Site: a\x01b"}, wantErr: true},
	}
	for _, tc := range cases {
		cmd := &cobra.Command{}
		apiClientFlags(cmd)
		if err := cmd.ParseFlags(tc.args); err != nil {
			t.Fatal(err)
		}
		h := http.Header{}
		err := customHeaders(cmd, "api-header", h)
		if tc.wantErr {
			if err == nil {
				t.Errorf("customHeaders(%q) = %v, want error", tc.args, h)
			}
			continue
		}
		if err != nil || !reflect.DeepEqual(h, tc.want) {
			t.Errorf("customHeaders(%q) = %v, %v; want %v", tc.args, h, err, tc.want)
		}
	}
}
