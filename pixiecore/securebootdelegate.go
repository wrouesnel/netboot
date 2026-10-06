package pixiecore

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/wrouesnel/netboot/pixiecore/uefisign"
)

// Headers sent to a SecureBootDelegate with each image to sign.
const (
	// HeaderPixiecoreMAC is the MAC address of the machine the image
	// is for.
	HeaderPixiecoreMAC = "X-Pixiecore-Mac"
	// HeaderPixiecoreImageType is the kind of image, ImageIpxe or
	// ImageKernel.
	HeaderPixiecoreImageType = "X-Pixiecore-Image-Type"
)

// ImageType is the kind of image a SecureBootDelegate is asked to sign.
type ImageType string

// Image types sent in HeaderPixiecoreImageType.
const (
	ImageIpxe   ImageType = "ipxe"
	ImageKernel ImageType = "kernel"
)

const (
	// delegateCacheSize is the number of signed images a
	// SecureBootDelegate keeps, so retried requests don't sign again.
	delegateCacheSize = 16
	// maxSignatureGrowth is how much larger than the image a signed
	// image can be, for the signature and its certificates.
	maxSignatureGrowth = 1 << 20
	// maxDelegateErrorBody is how much of an error response is logged.
	maxDelegateErrorBody = 512
)

// A SecureBootDelegate signs UEFI images for Secure Boot by sending
// them to a remote signing service, which returns them signed for the
// machine they're for.
//
// The image is POSTed to URL as application/octet-stream, with
// HeaderPixiecoreMAC and HeaderPixiecoreImageType. A 200 response's
// body is the signed image. Any other response is an error. The signed
// image must be the same image with at least one more signature
// (see uefisign.CheckSigned).
type SecureBootDelegate struct {
	// URL of the signing service. Must be https.
	URL string
	// Client makes requests to URL, with its TLS settings, client
	// certificate and timeout. See NewAPIClient.
	Client *http.Client

	mu    sync.Mutex
	cache map[delegateKey]*list.Element
	lru   list.List // of *delegateEntry, most recently used first
}

type delegateKey struct {
	mac    string
	kind   ImageType
	digest [sha256.Size]byte
}

type delegateEntry struct {
	key    delegateKey
	done   chan struct{}
	signed []byte
	err    error
}

// Sign returns image signed for the machine with MAC mac. It returns an
// error wrapping uefisign.ErrNotPE, without contacting the signing
// service, if image isn't a UEFI image.
//
// Concurrent and recent requests for the same image and machine share
// a result. The returned slice is shared, so must not be modified.
func (d *SecureBootDelegate) Sign(ctx context.Context, mac net.HardwareAddr, kind ImageType, image []byte) ([]byte, error) {
	if err := uefisign.IsPE(image); err != nil {
		return nil, err
	}
	key := delegateKey{mac: mac.String(), kind: kind, digest: sha256.Sum256(image)}

	d.mu.Lock()
	if d.cache == nil {
		d.cache = map[delegateKey]*list.Element{}
	}
	if el, ok := d.cache[key]; ok {
		d.lru.MoveToFront(el)
		e := el.Value.(*delegateEntry)
		d.mu.Unlock()
		select {
		case <-e.done:
			return e.signed, e.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	e := &delegateEntry{key: key, done: make(chan struct{})}
	d.cache[key] = d.lru.PushFront(e)
	d.mu.Unlock()

	// The request isn't tied to ctx, since other callers may be waiting
	// for it. Client's timeout limits it.
	e.signed, e.err = d.sign(mac, kind, image)
	close(e.done)

	d.mu.Lock()
	if e.err != nil {
		// Don't keep failures, so the next request tries again.
		if el, ok := d.cache[key]; ok && el.Value == e {
			d.lru.Remove(el)
			delete(d.cache, key)
		}
	}
	for d.lru.Len() > delegateCacheSize {
		el := d.lru.Back()
		old := el.Value.(*delegateEntry)
		select {
		case <-old.done:
		default:
			// Still signing, and the oldest. Leave it to finish.
			d.mu.Unlock()
			return e.signed, e.err
		}
		d.lru.Remove(el)
		delete(d.cache, old.key)
	}
	d.mu.Unlock()
	return e.signed, e.err
}

func (d *SecureBootDelegate) sign(mac net.HardwareAddr, kind ImageType, image []byte) ([]byte, error) {
	req, err := http.NewRequest(http.MethodPost, d.URL, bytes.NewReader(image))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set(HeaderPixiecoreMAC, mac.String())
	req.Header.Set(HeaderPixiecoreImageType, string(kind))
	resp, err := d.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, maxDelegateErrorBody))
		return nil, fmt.Errorf("signing service returned %s: %q", resp.Status, strings.TrimSpace(string(msg)))
	}
	limit := int64(len(image)) + maxSignatureGrowth
	signed, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("reading the signed image: %w", err)
	}
	if int64(len(signed)) > limit {
		return nil, fmt.Errorf("signed image is too large (over %d bytes)", limit)
	}
	if err := uefisign.CheckSigned(image, signed); err != nil {
		return nil, fmt.Errorf("signing service returned a bad image: %w", err)
	}
	return signed, nil
}
