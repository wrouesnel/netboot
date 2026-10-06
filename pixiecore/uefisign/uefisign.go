// Package uefisign signs UEFI images, such as iPXE and Linux kernels
// with an EFI stub, for UEFI Secure Boot.
//
// Images are signed with an Authenticode signature, which is appended
// to any signatures the image already has. Firmware accepts an image
// if any of its signatures chains to a certificate in its db (and none
// is in dbx), so an image signed by a distribution still boots on
// machines that trust the distribution.
package uefisign // import "github.com/wrouesnel/netboot/pixiecore/uefisign"

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"

	"github.com/foxboron/go-uefi/authenticode"
	"github.com/foxboron/go-uefi/pkcs7"
)

// ErrNotPE is returned when signing an image that isn't a PE/COFF
// binary, such as a Linux kernel built without an EFI stub.
var ErrNotPE = errors.New("not a PE/COFF image")

// CacheSize is the number of signed images a Signer keeps.
const CacheSize = 8

// A Signer signs UEFI images, and caches the results so that images
// served repeatedly are only signed once.
type Signer struct {
	key   crypto.Signer
	chain []*x509.Certificate

	mu sync.Mutex
	// cache holds the most recently used images last.
	cache []*cacheEntry
}

type cacheEntry struct {
	hash [sha256.Size]byte
	// done is closed once signed and err are set.
	done   chan struct{}
	signed []byte
	err    error
}

// New returns a Signer that signs with key. chain is the signing
// certificate for key, followed by any intermediate certificates
// between it and the certificate in the machines' db, which are
// embedded in the signatures.
//
// key must be an RSA key, the only kind firmware generally verifies.
func New(key crypto.Signer, chain []*x509.Certificate) (*Signer, error) {
	if len(chain) == 0 {
		return nil, errors.New("no signing certificate")
	}
	if _, ok := key.Public().(*rsa.PublicKey); !ok {
		return nil, fmt.Errorf("the signing key must be an RSA key, got %T", key.Public())
	}
	pub, ok := chain[0].PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(key.Public()) {
		return nil, errors.New("the signing certificate doesn't match the key")
	}
	return &Signer{key: key, chain: chain}, nil
}

// Certificate returns the signing certificate.
func (s *Signer) Certificate() *x509.Certificate {
	return s.chain[0]
}

// Sign returns image with a signature appended. It returns an error
// wrapping ErrNotPE if image isn't a PE/COFF binary.
//
// The returned slice may be shared with other callers, and must not be
// modified.
func (s *Signer) Sign(image []byte) ([]byte, error) {
	hash := sha256.Sum256(image)

	s.mu.Lock()
	for i, e := range s.cache {
		if e.hash == hash {
			s.cache = append(append(s.cache[:i:i], s.cache[i+1:]...), e)
			s.mu.Unlock()
			<-e.done
			return e.signed, e.err
		}
	}
	e := &cacheEntry{hash: hash, done: make(chan struct{})}
	s.cache = append(s.cache, e)
	if len(s.cache) > CacheSize {
		s.cache = s.cache[len(s.cache)-CacheSize:]
	}
	s.mu.Unlock()

	// Concurrent requests for the same image wait for this one.
	e.signed, e.err = s.sign(image)
	close(e.done)
	if e.err != nil && !errors.Is(e.err, ErrNotPE) {
		// Don't remember errors that might be temporary, such as the
		// TPM being busy.
		s.mu.Lock()
		for i, c := range s.cache {
			if c == e {
				s.cache = append(s.cache[:i:i], s.cache[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
	}
	return e.signed, e.err
}

func (s *Signer) sign(image []byte) ([]byte, error) {
	if !bytes.HasPrefix(image, []byte("MZ")) {
		return nil, ErrNotPE
	}
	pe, err := authenticode.Parse(bytes.NewReader(image))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrNotPE, err)
	}
	if _, err := pe.Sign(s.key, s.chain[0], pkcs7.WithAdditionalCerts(s.chain[1:])); err != nil {
		return nil, err
	}
	return pe.Bytes(), nil
}

// Verify reports whether image has a valid signature made with cert's
// key. It doesn't check that cert is trusted.
func Verify(image []byte, cert *x509.Certificate) (bool, error) {
	pe, err := authenticode.Parse(bytes.NewReader(image))
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrNotPE, err)
	}
	ok, err := pe.Verify(cert)
	if errors.Is(err, authenticode.ErrNoSignatures) || errors.Is(err, authenticode.ErrNoValidSignatures) {
		return false, nil
	}
	return ok, err
}

// IsPE returns an error wrapping ErrNotPE if image isn't a PE/COFF
// binary, so can't be signed.
func IsPE(image []byte) error {
	if _, err := authenticode.Parse(bytes.NewReader(image)); err != nil {
		return fmt.Errorf("%w: %w", ErrNotPE, err)
	}
	return nil
}

// CheckSigned checks that signed is original with more signatures, or
// a signature original doesn't have, as returned by a remote signer.
// Original's signatures can be kept or replaced. The Authenticode digest covers everything
// but the signatures, so a different program, or changes to original,
// are rejected. It doesn't check who signed it.
func CheckSigned(original, signed []byte) error {
	orig, err := authenticode.Parse(bytes.NewReader(original))
	if err != nil {
		return fmt.Errorf("%w: %w", ErrNotPE, err)
	}
	pe, err := authenticode.Parse(bytes.NewReader(signed))
	if err != nil {
		return fmt.Errorf("signed image isn't a PE/COFF binary: %w", err)
	}
	if !bytes.Equal(orig.Hash(crypto.SHA256), pe.Hash(crypto.SHA256)) {
		return errors.New("signed image isn't the image that was sent")
	}
	before, err := orig.Signatures()
	if err != nil {
		return fmt.Errorf("reading the image's signatures: %w", err)
	}
	after, err := pe.Signatures()
	if err != nil {
		return fmt.Errorf("reading the signed image's signatures: %w", err)
	}
	if len(after) > len(before) {
		return nil
	}
	existing := map[string]bool{}
	for _, sig := range before {
		existing[string(sig.Certificate)] = true
	}
	for _, sig := range after {
		if !existing[string(sig.Certificate)] {
			return nil
		}
	}
	return fmt.Errorf("signed image has no new signature (%d signatures, the image had %d)", len(after), len(before))
}
