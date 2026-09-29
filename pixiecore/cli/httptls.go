package cli

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"
	"github.com/wrouesnel/netboot/pixiecore"
	"github.com/wrouesnel/netboot/pixiecore/ipxetrust"
)

// firmwareNames describe the iPXE binaries in messages.
var firmwareNames = map[pixiecore.Firmware]string{
	pixiecore.FirmwareX86PC:   "BIOS",
	pixiecore.FirmwareEFI32:   "32-bit UEFI",
	pixiecore.FirmwareEFI64:   "64-bit UEFI",
	pixiecore.FirmwareEFIBC:   "64-bit UEFI (BC)",
	pixiecore.FirmwareX86Ipxe: "iPXE chainload",
}

func httpTLSFlags(cmd *cobra.Command) {
	cmd.Flags().String("http-tls-cert", "", "PEM certificate chain to serve boot files over HTTPS with on --https-port, and boot machines over HTTPS. The last certificate in the file is trusted by the iPXE binaries")
	cmd.Flags().String("http-tls-key", "", "PEM private key for --http-tls-cert")
	cmd.Flags().Int("https-port", 443, "Port to listen on for HTTPS, with --http-tls-cert")
	cmd.Flags().Bool("http-disabled", false, "Don't listen for HTTP on --port. Requires HTTPS, with --http-tls-cert")
	cmd.Flags().String("http-host", "", "Host name machines use to reach Pixiecore's HTTP(S) server (default: Pixiecore's IP address)")
	cmd.Flags().StringSlice("ipxe-trust-cert", nil, fmt.Sprintf("PEM files of certificates for the iPXE binaries to trust for HTTPS, replacing the certificates built in. Only UEFI binaries can be changed. At most %d certificates", ipxetrust.Slots))
}

// httpTLSFromFlags configures s to serve boot files over HTTPS, and
// patches its iPXE binaries to trust the configured certificates.
func httpTLSFromFlags(cmd *cobra.Command, s *pixiecore.Server) {
	var err error
	certFile := mustGetString(cmd, "http-tls-cert")
	keyFile := mustGetString(cmd, "http-tls-key")
	s.HTTPHost = mustGetString(cmd, "http-host")
	if s.DisableHTTP, err = cmd.Flags().GetBool("http-disabled"); err != nil {
		fatalf("Error reading flag: %s", err)
	}
	if s.HTTPSPort, err = cmd.Flags().GetInt("https-port"); err != nil {
		fatalf("Error reading flag: %s", err)
	}
	trustFiles, err := cmd.Flags().GetStringSlice("ipxe-trust-cert")
	if err != nil {
		fatalf("Error reading flag: %s", err)
	}

	var trusted []*x509.Certificate
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			fatalf("--http-tls-cert and --http-tls-key must be used together")
		}
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			fatalf("Couldn't load HTTP TLS certificate: %s", err)
		}
		// iPXE verifies the chain the server sends, so it trusts
		// the last certificate in it.
		root, err := x509.ParseCertificate(cert.Certificate[len(cert.Certificate)-1])
		if err != nil {
			fatalf("Couldn't parse --http-tls-cert %q: %s", certFile, err)
		}
		trusted = append(trusted, root)
		s.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		if s.HTTPSPort <= 0 {
			fatalf("HTTPS port must be >0")
		}
		if !s.DisableHTTP && s.HTTPSPort == s.HTTPPort {
			fatalf("--https-port and --port must be different")
		}
	} else if s.DisableHTTP {
		fatalf("--http-disabled requires HTTPS, set --http-tls-cert and --http-tls-key")
	}
	for _, file := range trustFiles {
		certs, err := readCertificates(file)
		if err != nil {
			fatalf("--ipxe-trust-cert: %s", err)
		}
		trusted = append(trusted, certs...)
	}
	if len(trusted) == 0 {
		return
	}

	patched, warnings, err := trustIpxe(s.Ipxe, trusted)
	if err != nil {
		fatalf("Couldn't set the certificates trusted by iPXE: %s", err)
	}
	s.Ipxe = patched
	for _, w := range warnings {
		fmt.Fprintf(os.Stderr, "WARNING: %s\n", w)
	}
}

// readCertificates reads the certificates in a PEM file.
func readCertificates(file string) ([]*x509.Certificate, error) {
	bs, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, bs = pem.Decode(bs)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found in %s", file)
	}
	return certs, nil
}

// trustIpxe returns a copy of the iPXE binaries patched to trust certs.
// Binaries that can't be patched are left as they are, with a warning.
func trustIpxe(ipxe map[pixiecore.Firmware][]byte, certs []*x509.Certificate) (map[pixiecore.Firmware][]byte, []string, error) {
	var fingerprints [][ipxetrust.FingerprintLen]byte
	seen := map[[ipxetrust.FingerprintLen]byte]bool{}
	for _, cert := range certs {
		fp := ipxetrust.Fingerprint(cert)
		if !seen[fp] {
			seen[fp] = true
			fingerprints = append(fingerprints, fp)
		}
	}

	fwtypes := make([]pixiecore.Firmware, 0, len(ipxe))
	for fwtype := range ipxe {
		fwtypes = append(fwtypes, fwtype)
	}
	sort.Slice(fwtypes, func(i, j int) bool { return fwtypes[i] < fwtypes[j] })

	ret := make(map[pixiecore.Firmware][]byte, len(ipxe))
	var warnings []string
	for _, fwtype := range fwtypes {
		name := firmwareNames[fwtype]
		if name == "" {
			name = fmt.Sprintf("firmware %d", fwtype)
		}
		bs, err := ipxetrust.Patch(ipxe[fwtype], fingerprints)
		switch {
		case errors.Is(err, ipxetrust.ErrNoTable):
			warnings = append(warnings, fmt.Sprintf("the %s iPXE binary can't be changed to trust the HTTPS certificates, and only trusts the certificates built into it", name))
			ret[fwtype] = ipxe[fwtype]
		case err != nil:
			return nil, nil, fmt.Errorf("%s iPXE binary: %w", name, err)
		default:
			ret[fwtype] = bs
		}
	}
	return ret, warnings, nil
}
