package uefisign_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/foxboron/go-uefi/authenticode"
	"github.com/wrouesnel/netboot/out/ipxe"
	"github.com/wrouesnel/netboot/pixiecore/uefisign"
)

func efiImage() []byte {
	return ipxe.MustAsset("third_party/ipxe/src/bin-x86_64-efi/ipxe.efi")
}

// newCert issues a code signing certificate for key, signed by parent
// and parentKey, or self-signed if parent is nil.
func newCert(t *testing.T, cn string, key crypto.Signer, isCA bool, parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if parent == nil {
		parent, parentKey = tmpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, key.Public(), parentKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func rsaKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// signatureCerts returns the certificates embedded in each of image's
// signatures.
func signatureCerts(t *testing.T, image []byte) [][]*x509.Certificate {
	t.Helper()
	pe, err := authenticode.Parse(bytes.NewReader(image))
	if err != nil {
		t.Fatal(err)
	}
	sigs, err := pe.Signatures()
	if err != nil {
		t.Fatal(err)
	}
	var ret [][]*x509.Certificate
	for _, sig := range sigs {
		a, err := authenticode.ParseAuthenticode(sig.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		ret = append(ret, a.Pkcs.Certs)
	}
	return ret
}

func TestSign(t *testing.T) {
	caKey, leafKey := rsaKey(t), rsaKey(t)
	ca := newCert(t, "db CA", caKey, true, nil, nil)
	leaf := newCert(t, "pixiecore", leafKey, false, ca, caKey)

	s, err := uefisign.New(leafKey, []*x509.Certificate{leaf, ca})
	if err != nil {
		t.Fatal(err)
	}
	image := efiImage()
	signed, err := s.Sign(image)
	if err != nil {
		t.Fatalf("Sign: %s", err)
	}
	if ok, err := uefisign.Verify(signed, leaf); !ok || err != nil {
		t.Fatalf("signed image doesn't verify: %v, %v", ok, err)
	}
	if ok, err := uefisign.Verify(image, leaf); ok || err != nil {
		t.Fatalf("unsigned image verifies: %v, %v", ok, err)
	}
	certs := signatureCerts(t, signed)
	if len(certs) != 1 || len(certs[0]) != 2 || !certs[0][0].Equal(leaf) || !certs[0][1].Equal(ca) {
		t.Fatalf("signature doesn't carry the certificate chain: %v", certs)
	}

	// Signing a signed image adds a second signature, and keeps the
	// first.
	otherKey := rsaKey(t)
	other := newCert(t, "other", otherKey, false, nil, nil)
	s2, err := uefisign.New(otherKey, []*x509.Certificate{other})
	if err != nil {
		t.Fatal(err)
	}
	twice, err := s2.Sign(signed)
	if err != nil {
		t.Fatalf("signing a signed image: %s", err)
	}
	for _, cert := range []*x509.Certificate{leaf, other} {
		if ok, err := uefisign.Verify(twice, cert); !ok || err != nil {
			t.Fatalf("twice signed image doesn't verify with %s: %v, %v", cert.Subject.CommonName, ok, err)
		}
	}
	if n := len(signatureCerts(t, twice)); n != 2 {
		t.Fatalf("twice signed image has %d signatures", n)
	}
}

func TestSignNotPE(t *testing.T) {
	key := rsaKey(t)
	s, err := uefisign.New(key, []*x509.Certificate{newCert(t, "pixiecore", key, false, nil, nil)})
	if err != nil {
		t.Fatal(err)
	}
	for _, image := range [][]byte{
		[]byte("not an image"),
		[]byte("MZ but not a PE image"),
		ipxe.MustAsset("third_party/ipxe/src/bin/undionly.kpxe"),
	} {
		if _, err := s.Sign(image); !errors.Is(err, uefisign.ErrNotPE) {
			t.Errorf("Sign(%.16q) = %v, want ErrNotPE", image, err)
		}
	}
}

func TestSignCache(t *testing.T) {
	key := rsaKey(t)
	s, err := uefisign.New(key, []*x509.Certificate{newCert(t, "pixiecore", key, false, nil, nil)})
	if err != nil {
		t.Fatal(err)
	}
	image := efiImage()

	// Concurrent requests for an image share one signature.
	results := make([][]byte, 8)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bs, err := s.Sign(image)
			if err != nil {
				t.Error(err)
			}
			results[i] = bs
		}()
	}
	wg.Wait()
	for _, bs := range results[1:] {
		if &bs[0] != &results[0][0] {
			t.Fatal("image was signed more than once")
		}
	}

	// Once CacheSize other images are signed, the image is signed
	// again.
	for i := range uefisign.CacheSize {
		other := bytes.Clone(image)
		other = append(other, byte(i))
		if _, err := s.Sign(other); err != nil {
			t.Fatal(err)
		}
	}
	again, err := s.Sign(image)
	if err != nil {
		t.Fatal(err)
	}
	if &again[0] == &results[0][0] {
		t.Fatal("image wasn't evicted from the cache")
	}
}

func TestNew(t *testing.T) {
	key := rsaKey(t)
	cert := newCert(t, "pixiecore", key, false, nil, nil)
	if _, err := uefisign.New(rsaKey(t), []*x509.Certificate{cert}); err == nil {
		t.Error("New accepted a certificate for another key")
	}
	if _, err := uefisign.New(key, nil); err == nil {
		t.Error("New accepted no certificate")
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := uefisign.New(ecKey, []*x509.Certificate{newCert(t, "pixiecore", ecKey, false, nil, nil)}); err == nil {
		t.Error("New accepted an ECDSA key")
	}
}

func TestCheckSigned(t *testing.T) {
	key := rsaKey(t)
	s, err := uefisign.New(key, []*x509.Certificate{newCert(t, "pixiecore", key, false, nil, nil)})
	if err != nil {
		t.Fatal(err)
	}
	image := efiImage()
	signed, err := s.Sign(image)
	if err != nil {
		t.Fatal(err)
	}
	if err := uefisign.CheckSigned(image, signed); err != nil {
		t.Errorf("CheckSigned(signed image): %s", err)
	}
	// Signing a signed image adds a signature.
	twice, err := s.Sign(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := uefisign.CheckSigned(signed, twice); err != nil {
		t.Errorf("CheckSigned(signed twice): %s", err)
	}

	// A signer can replace the existing signatures.
	if err := uefisign.CheckSigned(signed, other(t, s, image)); err != nil {
		t.Errorf("CheckSigned(replaced signature): %s", err)
	}

	if err := uefisign.CheckSigned(image, image); err == nil {
		t.Error("CheckSigned accepted an unsigned image")
	}
	if err := uefisign.CheckSigned(signed, signed); err == nil {
		t.Error("CheckSigned accepted an image with no new signature")
	}
	// A different program, signed.
	different, err := s.Sign(ipxe.MustAsset("third_party/ipxe/src/bin-i386-efi/ipxe.efi"))
	if err != nil {
		t.Fatal(err)
	}
	if err := uefisign.CheckSigned(image, different); err == nil {
		t.Error("CheckSigned accepted a different program")
	}
	// The same program, changed after signing.
	tampered := bytes.Clone(signed)
	tampered[len(image)/2] ^= 0xff
	if err := uefisign.CheckSigned(image, tampered); err == nil {
		t.Error("CheckSigned accepted a changed program")
	}
	if err := uefisign.CheckSigned(image, []byte("not a PE")); err == nil {
		t.Error("CheckSigned accepted a non-PE response")
	}
	if err := uefisign.CheckSigned([]byte("not a PE"), signed); !errors.Is(err, uefisign.ErrNotPE) {
		t.Errorf("CheckSigned(non-PE original) = %v, want ErrNotPE", err)
	}
	if err := uefisign.IsPE(image); err != nil {
		t.Errorf("IsPE(ipxe.efi): %s", err)
	}
	if err := uefisign.IsPE([]byte("not a PE")); !errors.Is(err, uefisign.ErrNotPE) {
		t.Errorf("IsPE(non-PE) = %v, want ErrNotPE", err)
	}
}

// other signs image with a new key, standing in for a signer that
// replaces existing signatures.
func other(t *testing.T, _ *uefisign.Signer, image []byte) []byte {
	t.Helper()
	key := rsaKey(t)
	s, err := uefisign.New(key, []*x509.Certificate{newCert(t, "other", key, false, nil, nil)})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := s.Sign(image)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
