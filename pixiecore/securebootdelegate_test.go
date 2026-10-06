package pixiecore

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wrouesnel/netboot/out/ipxe"
	"github.com/wrouesnel/netboot/pixiecore/uefisign"
)

// signingService is a fake delegate signing service, which requires a
// client certificate.
type signingService struct {
	srv    *httptest.Server
	signer *uefisign.Signer
	cert   *x509.Certificate
	calls  atomic.Int32
	// release, if set, holds requests until it's closed.
	release chan struct{}

	mu       sync.Mutex
	requests []string // "mac type"
}

// Behaviours chosen by MAC address.
const (
	macRefused = "02:00:00:00:00:03"
	macSwapped = "02:00:00:00:00:04"
)

func newSigningService(t *testing.T) (*signingService, tls.Certificate) {
	t.Helper()
	signer, cert := testSigner(t)
	ss := &signingService{signer: signer, cert: cert}
	ss.srv = httptest.NewUnstartedServer(http.HandlerFunc(ss.handle))

	client := delegateClientCert(t)
	pool := x509.NewCertPool()
	pool.AddCert(client.Leaf)
	ss.srv.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}
	ss.srv.StartTLS()
	t.Cleanup(ss.srv.Close)
	return ss, client
}

func (ss *signingService) handle(w http.ResponseWriter, r *http.Request) {
	ss.calls.Add(1)
	if ss.release != nil {
		<-ss.release
	}
	mac, kind := r.Header.Get(HeaderPixiecoreMAC), r.Header.Get(HeaderPixiecoreImageType)
	ss.mu.Lock()
	ss.requests = append(ss.requests, mac+" "+kind)
	ss.mu.Unlock()
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/octet-stream" {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	image, _ := io.ReadAll(r.Body)
	switch mac {
	case macRefused:
		http.Error(w, "not allowed to boot", http.StatusForbidden)
		return
	case macSwapped:
		image = ipxe.MustAsset("third_party/ipxe/src/bin-i386-efi/ipxe.efi")
	}
	signed, err := ss.signer.Sign(image)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(signed)
}

// delegate returns a SecureBootDelegate for the service, presenting
// client.
func (ss *signingService) delegate(t *testing.T, client *tls.Certificate) *SecureBootDelegate {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(ss.srv.Certificate())
	c, err := NewAPIClient(ss.srv.URL, APIClientConfig{RootCAs: roots, ClientCertificate: client, Timeout: 10 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	return &SecureBootDelegate{URL: ss.srv.URL, Client: c}
}

func delegateClientCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "pixiecore"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

func TestSecureBootDelegate(t *testing.T) {
	ss, client := newSigningService(t)
	d := ss.delegate(t, &client)
	image := ipxe.MustAsset("third_party/ipxe/src/bin-x86_64-efi/ipxe.efi")
	mac := mustMAC("02:00:00:00:00:01")
	ctx := context.Background()

	signed, err := d.Sign(ctx, mac, ImageIpxe, image)
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := uefisign.Verify(signed, ss.cert); !ok || err != nil {
		t.Fatalf("delegate result isn't signed by the service: %v", err)
	}
	if got := strings.Join(ss.requests, ","); got != "02:00:00:00:00:01 ipxe" {
		t.Errorf("service got requests %q", got)
	}

	// The same request is answered from the cache, but other machines
	// and image types are signed separately.
	if _, err := d.Sign(ctx, mac, ImageIpxe, image); err != nil {
		t.Fatal(err)
	}
	if n := ss.calls.Load(); n != 1 {
		t.Errorf("%d calls after a repeated request, want 1", n)
	}
	if _, err := d.Sign(ctx, mustMAC("02:00:00:00:00:02"), ImageIpxe, image); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Sign(ctx, mac, ImageKernel, image); err != nil {
		t.Fatal(err)
	}
	if n := ss.calls.Load(); n != 3 {
		t.Errorf("%d calls, want 3", n)
	}

	// Images that aren't UEFI images aren't sent.
	if _, err := d.Sign(ctx, mac, ImageKernel, []byte("not a PE")); !errors.Is(err, uefisign.ErrNotPE) {
		t.Errorf("Sign(non-PE) = %v, want ErrNotPE", err)
	}
	if n := ss.calls.Load(); n != 3 {
		t.Errorf("non-PE image was sent to the service")
	}

	// Errors aren't cached.
	for i := 0; i < 2; i++ {
		if _, err := d.Sign(ctx, mustMAC(macRefused), ImageIpxe, image); err == nil || !strings.Contains(err.Error(), "not allowed to boot") {
			t.Errorf("Sign for a refused machine = %v, want the service's error", err)
		}
	}
	if n := ss.calls.Load(); n != 5 {
		t.Errorf("%d calls, want 5: errors were cached", n)
	}

	// A different program, even if signed, is rejected.
	if _, err := d.Sign(ctx, mustMAC(macSwapped), ImageIpxe, image); err == nil || !strings.Contains(err.Error(), "isn't the image that was sent") {
		t.Errorf("Sign with a swapped image = %v, want an error", err)
	}
}

func TestSecureBootDelegateTLS(t *testing.T) {
	ss, client := newSigningService(t)
	image := ipxe.MustAsset("third_party/ipxe/src/bin-x86_64-efi/ipxe.efi")
	mac := mustMAC("02:00:00:00:00:01")

	// Without the client certificate, the service refuses the
	// connection.
	if _, err := ss.delegate(t, nil).Sign(context.Background(), mac, ImageIpxe, image); err == nil {
		t.Error("Sign succeeded without a client certificate")
	}
	// Another client certificate isn't trusted either.
	other := delegateClientCert(t)
	if _, err := ss.delegate(t, &other).Sign(context.Background(), mac, ImageIpxe, image); err == nil {
		t.Error("Sign succeeded with an untrusted client certificate")
	}
	// The service's certificate must be trusted.
	c, err := NewAPIClient(ss.srv.URL, APIClientConfig{ClientCertificate: &client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (&SecureBootDelegate{URL: ss.srv.URL, Client: c}).Sign(context.Background(), mac, ImageIpxe, image); err == nil {
		t.Error("Sign succeeded with an untrusted service certificate")
	}
	if n := ss.calls.Load(); n != 0 {
		t.Errorf("service handled %d requests over untrusted connections", n)
	}
}

func TestSecureBootDelegateConcurrent(t *testing.T) {
	ss, client := newSigningService(t)
	ss.release = make(chan struct{})
	d := ss.delegate(t, &client)
	image := ipxe.MustAsset("third_party/ipxe/src/bin-x86_64-efi/ipxe.efi")
	mac := mustMAC("02:00:00:00:00:01")

	// Retried TFTP requests share one signing request.
	var wg sync.WaitGroup
	results := make([][]byte, 5)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			signed, err := d.Sign(context.Background(), mac, ImageIpxe, image)
			if err != nil {
				t.Error(err)
			}
			results[i] = signed
		}()
	}
	for ss.calls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	close(ss.release)
	wg.Wait()
	if n := ss.calls.Load(); n != 1 {
		t.Errorf("%d calls for concurrent requests, want 1", n)
	}
	for _, r := range results[1:] {
		if !bytes.Equal(r, results[0]) {
			t.Error("concurrent requests got different results")
		}
	}

	// A waiter gives up when its context ends, without stopping the
	// signing for others.
	ss.release = make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	go func() { _, _ = d.Sign(context.Background(), mac, ImageKernel, image) }()
	for ss.calls.Load() < 2 {
		time.Sleep(time.Millisecond)
	}
	if _, err := d.Sign(ctx, mac, ImageKernel, image); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Sign with an expired context = %v, want DeadlineExceeded", err)
	}
	close(ss.release)
}

func TestSecureBootDelegateCacheLimit(t *testing.T) {
	ss, client := newSigningService(t)
	d := ss.delegate(t, &client)
	image := ipxe.MustAsset("third_party/ipxe/src/bin-x86_64-efi/ipxe.efi")
	for i := 0; i < delegateCacheSize+4; i++ {
		mac := net.HardwareAddr{2, 0, 0, 0, 1, byte(i)}
		if _, err := d.Sign(context.Background(), mac, ImageIpxe, image); err != nil {
			t.Fatal(err)
		}
	}
	if n := d.lru.Len(); n != delegateCacheSize || len(d.cache) != delegateCacheSize {
		t.Errorf("cache has %d/%d entries, want %d", n, len(d.cache), delegateCacheSize)
	}
	// The oldest was evicted, the newest kept.
	calls := ss.calls.Load()
	if _, err := d.Sign(context.Background(), net.HardwareAddr{2, 0, 0, 0, 1, byte(delegateCacheSize + 3)}, ImageIpxe, image); err != nil {
		t.Fatal(err)
	}
	if ss.calls.Load() != calls {
		t.Error("newest entry was evicted")
	}
	if _, err := d.Sign(context.Background(), net.HardwareAddr{2, 0, 0, 0, 1, 0}, ImageIpxe, image); err != nil {
		t.Fatal(err)
	}
	if ss.calls.Load() != calls+1 {
		t.Error("oldest entry wasn't evicted")
	}
}

func TestSecureBootDelegateServer(t *testing.T) {
	ss, client := newSigningService(t)
	efi := ipxe.MustAsset("third_party/ipxe/src/bin-x86_64-efi/ipxe.efi")
	bios := ipxe.MustAsset("third_party/ipxe/src/bin/undionly.kpxe")
	s := &Server{
		Booter: fileBooter{kernel: "kernel", files: map[ID][]byte{"kernel": efi}},
		Ipxe: map[Firmware][]byte{
			FirmwareX86PC: bios,
			FirmwareEFI64: efi,
		},
		SecureBootDelegate: ss.delegate(t, &client),
		events:             map[string][]machineEvent{},
		Log:                func(subsystem, msg string) { t.Logf("[%s] %s", subsystem, msg) },
	}
	s.Debug = s.Log
	signed := func(bs []byte) bool {
		ok, err := uefisign.Verify(bs, ss.cert)
		return ok && err == nil
	}
	tftp := func(path string) []byte {
		t.Helper()
		f, _, err := s.handleTFTP(path, &net.UDPAddr{})
		if err != nil {
			t.Fatalf("TFTP %s: %s", path, err)
		}
		bs, _ := io.ReadAll(f)
		return bs
	}

	// UEFI iPXE is signed for the machine fetching it, BIOS iPXE is
	// served as it is.
	if !signed(tftp("02:00:00:00:00:01/2")) {
		t.Error("UEFI iPXE isn't signed")
	}
	if !bytes.Equal(tftp("02:00:00:00:00:01/0"), bios) {
		t.Error("BIOS iPXE was changed")
	}
	// If signing fails, iPXE is served unsigned.
	if !bytes.Equal(tftp(macRefused+"/2"), efi) {
		t.Error("iPXE wasn't served unsigned when signing failed")
	}

	// Offering a boot signs iPXE ahead of the TFTP request.
	calls := ss.calls.Load()
	s.prefetchIpxe(mustMAC("02:00:00:00:00:05"), FirmwareEFI64)
	for ss.calls.Load() == calls {
		time.Sleep(time.Millisecond)
	}
	if !signed(tftp("02:00:00:00:00:05/2")) {
		t.Error("prefetched iPXE isn't signed")
	}
	if n := ss.calls.Load(); n != calls+1 {
		t.Errorf("%d calls for a prefetched iPXE, want 1", n-calls)
	}

	// The kernel in the boot script is signed for the machine.
	get := func(u string) []byte {
		rr := httptest.NewRecorder()
		s.serveHTTPForTest(rr, httptest.NewRequest(http.MethodGet, u, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s: %d", u, rr.Code)
		}
		return rr.Body.Bytes()
	}
	script := get("/_/ipxe?mac=02:00:00:00:00:06&arch=1")
	m := regexp.MustCompile(`kernel --name kernel http://[^/]+(\S+)`).FindSubmatch(script)
	if m == nil {
		t.Fatalf("no kernel in boot script:\n%s", script)
	}
	if !signed(get(string(m[1]))) {
		t.Error("kernel isn't signed")
	}
	ss.mu.Lock()
	last := ss.requests[len(ss.requests)-1]
	ss.mu.Unlock()
	if last != "02:00:00:00:00:06 kernel" {
		t.Errorf("service's last request was %q, want the kernel for 02:00:00:00:00:06", last)
	}

	// Pixiecore refuses to start with both kinds of signing.
	s.SecureBootSigner, _ = testSigner(t)
	if err := s.Serve(); err == nil || !strings.Contains(err.Error(), "can't both be set") {
		t.Errorf("Serve with both signers = %v", err)
	}
}
