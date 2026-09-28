package pixiecore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testClientCert issues a client certificate signed by a new CA, and
// returns the CA pool and the certificate.
func testClientCert(t *testing.T) (*x509.CertPool, *tls.Certificate) {
	t.Helper()
	mk := func(tmpl, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert, key
	}
	now := time.Now()
	ca, caKey := mk(&x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}, nil, nil)
	leaf, leafKey := mk(&x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "pixiecore"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, ca, caKey)

	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool, &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: leafKey, Leaf: leaf}
}

// authLog records the Authorization header of each request to a server.
type authLog struct {
	sync.Mutex
	m map[string]string
}

func (a *authLog) record(r *http.Request) {
	a.Lock()
	defer a.Unlock()
	a.m[r.URL.Path] = r.Header.Get("Authorization")
}

func (a *authLog) get(path string) (string, bool) {
	a.Lock()
	defer a.Unlock()
	v, ok := a.m[path]
	return v, ok
}

func TestAPIBooterTLS(t *testing.T) {
	clientCAs, clientCert := testClientCert(t)

	// A second server on a different origin, which serves the initrd.
	// It must never see the API credentials.
	otherLog := &authLog{m: map[string]string{}}
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherLog.record(r)
		_, _ = w.Write([]byte("other file"))
	}))
	defer other.Close()

	apiLog := &authLog{m: map[string]string{}}
	api := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiLog.record(r)
		if u, p, ok := r.BasicAuth(); !ok || u != "user" || p != "secret" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/boot/01:02:03:04:05:06":
			fmt.Fprintf(w, `{"kernel": "/kernel", "initrd": ["%s/initrd"]}`, other.URL)
		case "/kernel":
			_, _ = w.Write([]byte("kernel file"))
		default:
			http.NotFound(w, r)
		}
	}))
	api.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientCAs}
	api.StartTLS()
	defer api.Close()

	// Trust both test servers' certificates.
	roots := x509.NewCertPool()
	roots.AddCert(api.Certificate())
	roots.AddCert(other.Certificate())

	m := Machine{MAC: mustMAC("01:02:03:04:05:06"), Arch: ArchX64}

	cases := []struct {
		name    string
		cfg     APIClientConfig
		wantErr string
	}{
		{
			name: "ok",
			cfg:  APIClientConfig{RootCAs: roots, ClientCertificate: clientCert, Username: "user", Password: "secret"},
		},
		{
			name:    "untrusted server",
			cfg:     APIClientConfig{ClientCertificate: clientCert, Username: "user", Password: "secret"},
			wantErr: "certificate",
		},
		{
			name: "untrusted server with InsecureSkipVerify",
			cfg:  APIClientConfig{InsecureSkipVerify: true, ClientCertificate: clientCert, Username: "user", Password: "secret"},
		},
		{
			name:    "no client certificate",
			cfg:     APIClientConfig{RootCAs: roots, Username: "user", Password: "secret"},
			wantErr: "certificate",
		},
		{
			name:    "wrong password",
			cfg:     APIClientConfig{RootCAs: roots, ClientCertificate: clientCert, Username: "user", Password: "wrong"},
			wantErr: "Unauthorized",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.cfg.Timeout = 5 * time.Second
			client, err := NewAPIClient(api.URL, tc.cfg)
			if err != nil {
				t.Fatalf("NewAPIClient: %s", err)
			}
			b, err := APIBooterWithClient(api.URL, client)
			if err != nil {
				t.Fatalf("APIBooterWithClient: %s", err)
			}

			spec, err := b.BootSpec(m)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("BootSpec: got error %v, want error containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("BootSpec: %s", err)
			}

			if v := mustRead(b.ReadBootFile(spec.Kernel)); v != "kernel file" {
				t.Errorf("kernel: got %q", v)
			}
			if v := mustRead(b.ReadBootFile(spec.Initrd[0])); v != "other file" {
				t.Errorf("initrd: got %q", v)
			}
			if auth, _ := apiLog.get("/kernel"); auth == "" {
				t.Errorf("kernel fetch from API server didn't send credentials")
			}
			if auth, ok := otherLog.get("/initrd"); !ok || auth != "" {
				t.Errorf("initrd fetch from another server: fetched=%v, Authorization=%q, want no credentials", ok, auth)
			}
		})
	}
}

func TestCanonicalHost(t *testing.T) {
	for in, want := range map[string]string{
		"http://Example.com/foo":     "example.com:80",
		"http://example.com:80/foo":  "example.com:80",
		"https://example.com/":       "example.com:443",
		"https://example.com:8443/":  "example.com:8443",
		"https://[2001:db8::1]/":     "[2001:db8::1]:443",
		"https://user@example.com/x": "example.com:443",
	} {
		u, err := http.NewRequest("GET", in, nil)
		if err != nil {
			t.Fatal(err)
		}
		if got := canonicalHost(u.URL); got != want {
			t.Errorf("canonicalHost(%q) = %q, want %q", in, got, want)
		}
	}
}
