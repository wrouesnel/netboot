package pixiecore

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/wrouesnel/netboot/pixiecore/uefisign"
)

// maxSignedKernelSize is the largest kernel Pixiecore reads into memory
// to sign. Larger kernels are served unsigned.
const maxSignedKernelSize = 256 << 20

// secureBootEnabled reports whether Pixiecore signs images, locally or
// through a delegate.
func (s *Server) secureBootEnabled() bool {
	return s.SecureBootSigner != nil || s.SecureBootDelegate != nil
}

// isUEFI reports whether fwtype boots UEFI iPXE binaries, which can be
// signed.
func isUEFI(fwtype Firmware) bool {
	return fwtype == FirmwareEFI32 || fwtype == FirmwareEFI64 || fwtype == FirmwareEFIBC
}

// kernelToken returns the value of the ksig parameter that marks id as
// the kernel from mac's boot spec, and so as something Pixiecore will
// sign for mac. Without it, anything Pixiecore serves could be fetched
// signed, by asking for it as a kernel, and a delegate could be asked
// to sign a kernel for another machine.
func (s *Server) kernelToken(id ID, mac net.HardwareAddr) string {
	s.kernelKeyOnce.Do(func() {
		s.kernelKey = make([]byte, 32)
		if _, err := rand.Read(s.kernelKey); err != nil {
			panic(fmt.Sprintf("generating kernel token key: %s", err))
		}
	})
	h := hmac.New(sha256.New, s.kernelKey)
	// The MAC is first, in a fixed format, and separated from the ID,
	// so different pairs can't hash the same input.
	h.Write([]byte(mac.String()))
	h.Write([]byte{0})
	h.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

// signImage signs image for mac, with the local signer or the
// delegate.
func (s *Server) signImage(ctx context.Context, mac net.HardwareAddr, kind ImageType, image []byte) ([]byte, error) {
	if s.SecureBootDelegate != nil {
		return s.SecureBootDelegate.Sign(ctx, mac, kind, image)
	}
	return s.SecureBootSigner.Sign(image)
}

// ipxeFor returns the iPXE binary for fwtype to serve to mac. With a
// delegate, UEFI binaries are signed for mac, or served unsigned if
// that fails. Otherwise they're served as they are, already signed if
// there's a local signer.
func (s *Server) ipxeFor(mac net.HardwareAddr, fwtype Firmware) []byte {
	bs := s.Ipxe[fwtype]
	if s.SecureBootDelegate == nil || !isUEFI(fwtype) || bs == nil {
		return bs
	}
	signed, err := s.SecureBootDelegate.Sign(context.Background(), mac, ImageIpxe, bs)
	if err != nil {
		s.log("SecureBoot", "Couldn't sign iPXE for %s, serving it unsigned: %s", mac, err)
		return bs
	}
	return signed
}

// prefetchIpxe starts signing the iPXE binary for mac, when it's
// offered a boot, so it's ready when mac fetches it.
func (s *Server) prefetchIpxe(mac net.HardwareAddr, fwtype Firmware) {
	if s.SecureBootDelegate != nil && isUEFI(fwtype) {
		go s.ipxeFor(mac, fwtype)
	}
}

// signKernel returns the kernel id, read from f, signed for mac, and
// its size. If the kernel can't be signed it is returned unsigned.
func (s *Server) signKernel(ctx context.Context, id ID, mac net.HardwareAddr, f io.Reader, size int64) (io.Reader, int64) {
	if size > maxSignedKernelSize {
		s.log("HTTP", "Kernel %q is too large to sign (%d bytes), serving it unsigned", id, size)
		return f, size
	}
	image, err := io.ReadAll(io.LimitReader(f, maxSignedKernelSize+1))
	if err != nil {
		// Serve what was read, so the transfer fails part way rather
		// than looking like an empty file.
		s.log("HTTP", "Reading kernel %q to sign it: %s", id, err)
		return io.MultiReader(bytes.NewReader(image), f), size
	}
	if len(image) > maxSignedKernelSize {
		s.log("HTTP", "Kernel %q is too large to sign, serving it unsigned", id)
		return io.MultiReader(bytes.NewReader(image), f), size
	}
	if size >= 0 && int64(len(image)) != size {
		s.log("HTTP", "Kernel %q is %d bytes, but should be %d bytes, serving it unsigned", id, len(image), size)
		return bytes.NewReader(image), int64(len(image))
	}

	signed, err := s.signImage(ctx, mac, ImageKernel, image)
	switch {
	case errors.Is(err, uefisign.ErrNotPE):
		s.debug("HTTP", "Kernel %q isn't a UEFI image, serving it unsigned: %s", id, err)
		return bytes.NewReader(image), int64(len(image))
	case err != nil:
		s.log("HTTP", "Couldn't sign kernel %q, serving it unsigned: %s", id, err)
		return bytes.NewReader(image), int64(len(image))
	}
	s.debug("HTTP", "Signed kernel %q for %s for Secure Boot", id, mac)
	return bytes.NewReader(signed), int64(len(signed))
}
