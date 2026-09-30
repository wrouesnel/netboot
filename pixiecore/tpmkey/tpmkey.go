// Package tpmkey manages TPM-resident keys and the X.509 certificates
// that go with them, for use in mTLS authentication and for signing
// UEFI Secure Boot images.
//
// The private key never leaves the TPM. It is stored on disk as a
// TSS2 PEM keyfile ("-----BEGIN TSS2 PRIVATE KEY-----"), which is
// wrapped by the TPM's storage root key and so is only usable on the
// TPM that created it. The format is shared with the OpenSSL tpm2
// provider and other tools.
package tpmkey // import "github.com/wrouesnel/netboot/pixiecore/tpmkey"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	keyfile "github.com/foxboron/go-tpm-keyfiles"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// DefaultDevice is the kernel's resource-managed TPM device. It is
// ignored on Windows, where the TPM is always accessed through TBS.
const DefaultDevice = "/dev/tpmrm0"

// KeyType is the kind of key LoadOrCreateKey creates.
type KeyType int

const (
	// KeyECDSAP256 is an ECDSA P-256 key, used for TLS client
	// certificates.
	KeyECDSAP256 KeyType = iota
	// KeyRSA2048 is an RSA 2048-bit key, used to sign UEFI Secure Boot
	// images. Firmware generally only verifies RSA 2048 signatures.
	KeyRSA2048
)

func (k KeyType) String() string {
	switch k {
	case KeyECDSAP256:
		return "ECDSA P-256"
	case KeyRSA2048:
		return "RSA 2048"
	default:
		return fmt.Sprintf("KeyType(%d)", int(k))
	}
}

// matches reports whether pub is a key of type k.
func (k KeyType) matches(pub crypto.PublicKey) bool {
	switch pub := pub.(type) {
	case *ecdsa.PublicKey:
		return k == KeyECDSAP256 && pub.Curve == elliptic.P256()
	case *rsa.PublicKey:
		return k == KeyRSA2048 && pub.N.BitLen() == 2048
	default:
		return false
	}
}

// LoadOrCreateKey reads the TSS2 keyfile at path, or creates a new
// signing key of type keyType in the TPM and saves it to path if the
// file does not exist. It is an error for an existing key to be of a
// different type. description is saved in new keyfiles.
//
// The key is created under the TPM's owner hierarchy, so ownerAuth
// must be the owner hierarchy password (normally empty).
func LoadOrCreateKey(tpm transport.TPMCloser, path string, ownerAuth []byte, keyType KeyType, description string) (key *keyfile.TPMKey, created bool, err error) {
	bs, err := os.ReadFile(path)
	if err == nil {
		key, err := keyfile.Decode(bs)
		if err != nil {
			return nil, false, fmt.Errorf("parsing TPM keyfile %q: %w", path, err)
		}
		pub, err := key.PublicKey()
		if err != nil {
			return nil, false, fmt.Errorf("TPM keyfile %q: %w", path, err)
		}
		if !keyType.matches(pub) {
			return nil, false, fmt.Errorf("TPM keyfile %q doesn't hold an %s key", path, keyType)
		}
		return key, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, err
	}

	alg, bits := tpm2.TPMAlgECC, 256
	switch keyType {
	case KeyECDSAP256:
	case KeyRSA2048:
		alg, bits = tpm2.TPMAlgRSA, 2048
	default:
		return nil, false, fmt.Errorf("unknown key type %s", keyType)
	}
	key, err = keyfile.NewLoadableKey(tpm, alg, bits, ownerAuth,
		keyfile.WithUserAuth(nil),
		keyfile.WithDescription(description),
	)
	if err != nil {
		return nil, false, fmt.Errorf("creating TPM key: %w", err)
	}
	if err := writeFileAtomic(path, key.Bytes(), 0o600); err != nil {
		return nil, false, fmt.Errorf("saving TPM keyfile: %w", err)
	}
	return key, true, nil
}

// Signer returns a crypto.Signer which signs with key inside tpm.
func Signer(tpm transport.TPMCloser, key *keyfile.TPMKey, ownerAuth []byte) (crypto.Signer, error) {
	return key.Signer(tpm, ownerAuth, nil)
}

// CertificateOptions controls the self-signed certificate created by
// LoadOrCreateCertificate.
type CertificateOptions struct {
	// CommonName is the subject CN. Defaults to the hostname.
	CommonName string
	// Validity is how long the certificate is valid for. Defaults to
	// 10 years.
	Validity time.Duration
	// Renew forces a new certificate to be issued even if a valid one
	// already exists.
	Renew bool
	// ExtKeyUsage is the extended key usage of the certificate.
	// Defaults to TLS client authentication.
	ExtKeyUsage []x509.ExtKeyUsage
}

// LoadOrCreateCertificate returns the certificate stored at path if it
// holds signer's public key, and otherwise issues a new self-signed
// certificate for signer and saves it to path.
//
// Certificates are only replaced automatically if they are missing or
// don't match the key, or if opts.Renew is set. An existing certificate is otherwise kept, so a
// CA-signed certificate can be put at path in place of the self-signed
// one.
func LoadOrCreateCertificate(signer crypto.Signer, path string, opts CertificateOptions) (cert *x509.Certificate, created bool, err error) {
	existing, err := ReadCertificate(path)
	switch {
	case err == nil:
		if !opts.Renew && matchesKey(existing, signer.Public()) {
			return existing, false, nil
		}
		// A replacement certificate keeps the existing subject, unless
		// told otherwise.
		if opts.CommonName == "" {
			opts.CommonName = existing.Subject.CommonName
		}
	case !errors.Is(err, os.ErrNotExist):
		return nil, false, err
	}

	cert, err = selfSign(signer, opts)
	if err != nil {
		return nil, false, err
	}
	if err := writeFileAtomic(path, EncodeCertificate(cert), 0o644); err != nil {
		return nil, false, fmt.Errorf("saving certificate: %w", err)
	}
	return cert, true, nil
}

// ReadCertificate reads the first PEM certificate in path.
func ReadCertificate(path string) (*x509.Certificate, error) {
	bs, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for {
		var block *pem.Block
		block, bs = pem.Decode(bs)
		if block == nil {
			return nil, fmt.Errorf("no certificate found in %q", path)
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

// EncodeCertificate PEM-encodes cert.
func EncodeCertificate(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// CertificateRequest returns a PEM-encoded certificate signing request
// for signer, so that the key can be certified by an external CA.
func CertificateRequest(signer crypto.Signer, commonName string) ([]byte, error) {
	cn, err := commonNameOrHostname(commonName)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, signer)
	if err != nil {
		return nil, fmt.Errorf("creating certificate request: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// TLSCertificate combines cert and signer into a certificate usable in
// a tls.Config.
func TLSCertificate(cert *x509.Certificate, signer crypto.Signer) (*tls.Certificate, error) {
	if !matchesKey(cert, signer.Public()) {
		return nil, errors.New("certificate does not match the TPM key")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("certificate is not valid now (valid %s to %s)", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}
	return &tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  signer,
		Leaf:        cert,
	}, nil
}

func selfSign(signer crypto.Signer, opts CertificateOptions) (*x509.Certificate, error) {
	cn, err := commonNameOrHostname(opts.CommonName)
	if err != nil {
		return nil, err
	}
	validity := opts.Validity
	if validity <= 0 {
		validity = 10 * 365 * 24 * time.Hour
	}
	extKeyUsage := opts.ExtKeyUsage
	if len(extKeyUsage) == 0 {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(validity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  extKeyUsage,
		// CA:FALSE. The self-signed certificate is trusted directly,
		// it must not be usable to issue other certificates.
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("creating certificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

func commonNameOrHostname(cn string) (string, error) {
	if cn != "" {
		return cn, nil
	}
	host, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("no common name given, and can't get hostname: %w", err)
	}
	return host, nil
}

func matchesKey(cert *x509.Certificate, pub crypto.PublicKey) bool {
	k, ok := pub.(interface{ Equal(crypto.PublicKey) bool })
	return ok && k.Equal(cert.PublicKey)
}

// writeFileAtomic writes data to a temporary file next to path, and
// renames it into place so readers never see a partial file.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
