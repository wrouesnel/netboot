// Package ipxetrust manages the table of trusted root certificates
// built into Pixiecore's iPXE binaries.
//
// iPXE trusts TLS certificate chains that end in a certificate whose
// SHA-256 fingerprint is in a table compiled into the binary. Pixiecore
// builds iPXE with a table of fixed size, which starts with a marker so
// that it can be found and rewritten in a built binary. The marker
// includes the table size, so tables of other sizes aren't matched. Unused slots
// hold a filler value. Neither the marker nor the filler is the
// fingerprint of any real certificate, so they never match.
//
// Only uncompressed binaries (the UEFI builds) can be patched. The BIOS
// builds are LZMA compressed, so their table is fixed at build time.
package ipxetrust

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
)

// Slots is the number of trusted fingerprints the table holds.
const Slots = 8

// FingerprintLen is the length of a certificate fingerprint.
const FingerprintLen = sha256.Size

// TableLen is the length of the table, including the marker.
const TableLen = (Slots + 1) * FingerprintLen

var (
	marker = sha256.Sum256([]byte(fmt.Sprintf("pixiecore ipxe trust table v1 slots=%d", Slots)))
	filler = sha256.Sum256([]byte("pixiecore ipxe trust table v1 unused slot"))
)

// IPXERootCA is the fingerprint of the iPXE project's root CA, which
// iPXE trusts by default. iPXE uses it to verify certificates from
// public CAs, by fetching cross-signed certificates from ca.ipxe.org.
var IPXERootCA = [FingerprintLen]byte{
	0x9f, 0xaf, 0x71, 0x7b, 0x7f, 0x8c, 0xa2, 0xf9, 0x3c, 0x25,
	0x6c, 0x79, 0xf8, 0xac, 0x55, 0x91, 0x89, 0x5d, 0x66, 0xd1,
	0xff, 0x3b, 0xee, 0x63, 0x97, 0xa7, 0x0d, 0x29, 0xc6, 0x5e,
	0xed, 0x1a,
}

// ErrNoTable is returned by Patch for binaries without a patchable
// table.
var ErrNoTable = errors.New("no patchable iPXE trust table found")

// Fingerprint returns the fingerprint iPXE uses to identify cert.
func Fingerprint(cert *x509.Certificate) [FingerprintLen]byte {
	return sha256.Sum256(cert.Raw)
}

// Table returns the table trusting fingerprints.
func Table(fingerprints [][FingerprintLen]byte) ([]byte, error) {
	if len(fingerprints) == 0 {
		return nil, errors.New("at least one trusted certificate is required")
	}
	if len(fingerprints) > Slots {
		return nil, fmt.Errorf("at most %d trusted certificates are supported, got %d", Slots, len(fingerprints))
	}
	table := make([]byte, 0, TableLen)
	table = append(table, marker[:]...)
	for _, fp := range fingerprints {
		table = append(table, fp[:]...)
	}
	for range Slots - len(fingerprints) {
		table = append(table, filler[:]...)
	}
	return table, nil
}

// CDefine returns the table as the value of iPXE's TRUSTED macro: a
// comma-separated list of bytes.
func CDefine(table []byte) string {
	var b strings.Builder
	for i, v := range table {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "0x%02x", v)
	}
	return b.String()
}

// Patch returns a copy of the iPXE binary image with its table replaced
// by one trusting fingerprints. It returns ErrNoTable if image has no
// table.
func Patch(image []byte, fingerprints [][FingerprintLen]byte) ([]byte, error) {
	table, err := Table(fingerprints)
	if err != nil {
		return nil, err
	}
	i := bytes.Index(image, marker[:])
	if i < 0 {
		return nil, ErrNoTable
	}
	if bytes.Contains(image[i+1:], marker[:]) {
		return nil, errors.New("iPXE binary has more than one trust table")
	}
	if len(image)-i < TableLen {
		return nil, errors.New("iPXE trust table is truncated")
	}
	patched := bytes.Clone(image)
	copy(patched[i:], table)
	return patched, nil
}

// Trusted returns the fingerprints trusted by the table in image.
func Trusted(image []byte) ([][FingerprintLen]byte, error) {
	i := bytes.Index(image, marker[:])
	if i < 0 {
		return nil, ErrNoTable
	}
	if len(image)-i < TableLen {
		return nil, errors.New("iPXE trust table is truncated")
	}
	var ret [][FingerprintLen]byte
	for s := 1; s <= Slots; s++ {
		var fp [FingerprintLen]byte
		copy(fp[:], image[i+s*FingerprintLen:])
		if fp != filler {
			ret = append(ret, fp)
		}
	}
	return ret, nil
}
