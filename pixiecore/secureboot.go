package pixiecore

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/wrouesnel/netboot/pixiecore/uefisign"
)

// maxSignedKernelSize is the largest kernel Pixiecore reads into memory
// to sign. Larger kernels are served unsigned.
const maxSignedKernelSize = 256 << 20

// kernelToken returns the value of the ksig parameter that marks id as
// a kernel from a boot spec, and so as something Pixiecore will sign.
// Without it, anything Pixiecore serves could be fetched signed, by
// asking for it as a kernel.
func (s *Server) kernelToken(id ID) string {
	s.kernelKeyOnce.Do(func() {
		s.kernelKey = make([]byte, 32)
		if _, err := rand.Read(s.kernelKey); err != nil {
			panic(fmt.Sprintf("generating kernel token key: %s", err))
		}
	})
	mac := hmac.New(sha256.New, s.kernelKey)
	mac.Write([]byte(id))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// signKernel returns the kernel id, read from f, signed with
// s.SecureBootSigner, and its size. If the kernel can't be signed it is
// returned unsigned.
func (s *Server) signKernel(id ID, f io.Reader, size int64) (io.Reader, int64) {
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

	signed, err := s.SecureBootSigner.Sign(image)
	switch {
	case errors.Is(err, uefisign.ErrNotPE):
		s.debug("HTTP", "Kernel %q isn't a UEFI image, serving it unsigned: %s", id, err)
		return bytes.NewReader(image), int64(len(image))
	case err != nil:
		s.log("HTTP", "Couldn't sign kernel %q, serving it unsigned: %s", id, err)
		return bytes.NewReader(image), int64(len(image))
	}
	s.debug("HTTP", "Signed kernel %q for Secure Boot", id)
	return bytes.NewReader(signed), int64(len(signed))
}
