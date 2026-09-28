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
	"testing"
	"time"

	"github.com/spf13/cobra"
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
