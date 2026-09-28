//go:build cgo

// The TPM simulator is built from the reference implementation with
// cgo.

package tpmkey_test

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/wrouesnel/netboot/pixiecore"
	"github.com/wrouesnel/netboot/pixiecore/tpmkey"
)

func TestTPMClientCertificate(t *testing.T) {
	tpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("opening TPM simulator: %s", err)
	}
	defer tpm.Close()

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "sub", "client.key")
	certPath := filepath.Join(dir, "sub", "client.crt")

	key, created, err := tpmkey.LoadOrCreateKey(tpm, keyPath, nil)
	if err != nil || !created {
		t.Fatalf("LoadOrCreateKey: created=%v err=%v", created, err)
	}
	if bs, err := os.ReadFile(keyPath); err != nil {
		t.Fatal(err)
	} else if block, _ := pem.Decode(bs); block == nil || block.Type != "TSS2 PRIVATE KEY" {
		t.Fatalf("keyfile isn't a TSS2 PEM key: %q", bs)
	}
	if fi, err := os.Stat(keyPath); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("keyfile mode: %v, %v", fi.Mode(), err)
	}

	// Loading the key again reads the file rather than making a new key.
	key2, created, err := tpmkey.LoadOrCreateKey(tpm, keyPath, nil)
	if err != nil || created {
		t.Fatalf("reloading key: created=%v err=%v", created, err)
	}
	pub1, _ := key.PublicKey()
	pub2, _ := key2.PublicKey()
	if !pub1.(interface{ Equal(crypto.PublicKey) bool }).Equal(pub2) {
		t.Fatal("reloaded key has a different public key")
	}

	signer, err := tpmkey.Signer(tpm, key2, nil)
	if err != nil {
		t.Fatalf("Signer: %s", err)
	}

	cert, created, err := tpmkey.LoadOrCreateCertificate(signer, certPath, tpmkey.CertificateOptions{CommonName: "test-client"})
	if err != nil || !created {
		t.Fatalf("LoadOrCreateCertificate: created=%v err=%v", created, err)
	}
	if cert.Subject.CommonName != "test-client" || cert.IsCA {
		t.Fatalf("bad certificate: CN=%q IsCA=%v", cert.Subject.CommonName, cert.IsCA)
	}
	if err := cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature); err != nil {
		t.Fatalf("certificate isn't correctly self-signed by the TPM: %s", err)
	}

	// The existing certificate is reused, unless renewal is forced.
	again, created, err := tpmkey.LoadOrCreateCertificate(signer, certPath, tpmkey.CertificateOptions{})
	if err != nil || created || !again.Equal(cert) {
		t.Fatalf("certificate wasn't reused: created=%v err=%v", created, err)
	}
	renewed, created, err := tpmkey.LoadOrCreateCertificate(signer, certPath, tpmkey.CertificateOptions{Renew: true})
	if err != nil || !created || renewed.Equal(cert) {
		t.Fatalf("certificate wasn't renewed: created=%v err=%v", created, err)
	}
	cert = renewed

	csrPEM, err := tpmkey.CertificateRequest(signer, "test-client")
	if err != nil {
		t.Fatalf("CertificateRequest: %s", err)
	}
	block, _ := pem.Decode(csrPEM)
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature: %s", err)
	}

	// Use the TPM key for mTLS to a server that trusts the exported
	// certificate.
	tlsCert, err := tpmkey.TLSCertificate(cert, signer)
	if err != nil {
		t.Fatalf("TLSCertificate: %s", err)
	}
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		trusted, err := tpmkey.ReadCertificate(certPath)
		if err != nil {
			t.Fatal(err)
		}
		clientCAs := x509.NewCertPool()
		clientCAs.AddCert(trusted)

		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, r.TLS.PeerCertificates[0].Subject.CommonName)
		}))
		srv.TLS = &tls.Config{
			ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs:  clientCAs,
			MinVersion: version,
			MaxVersion: version,
		}
		srv.StartTLS()

		roots := x509.NewCertPool()
		roots.AddCert(srv.Certificate())
		client, err := pixiecore.NewAPIClient(srv.URL, pixiecore.APIClientConfig{
			Timeout:           10 * time.Second,
			RootCAs:           roots,
			ClientCertificate: tlsCert,
		})
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Get(srv.URL)
		if err != nil {
			t.Fatalf("TLS %x: request with TPM client cert: %s", version, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		srv.Close()
		if string(body) != "test-client" {
			t.Fatalf("TLS %x: server saw client %q", version, body)
		}
	}
}
