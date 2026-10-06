package pixiecore

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/wrouesnel/netboot/out/ipxe"
	"github.com/wrouesnel/netboot/pixiecore/uefisign"
)

// fileBooter boots every machine into kernel, and serves files.
type fileBooter struct {
	kernel ID
	files  map[ID][]byte
}

func (b fileBooter) BootSpec(m Machine) (*Spec, error) {
	return &Spec{Kernel: b.kernel, Cmdline: `f={{ ID "other" }}`}, nil
}
func (b fileBooter) ReadBootFile(id ID) (io.ReadCloser, int64, error) {
	bs, ok := b.files[id]
	if !ok {
		return nil, -1, errors.New("no such file")
	}
	return io.NopCloser(bytes.NewReader(bs)), int64(len(bs)), nil
}
func (b fileBooter) WriteBootFile(id ID, r io.Reader) error { return errors.New("no") }

func testSigner(t *testing.T) (*uefisign.Signer, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	s, err := uefisign.New(key, []*x509.Certificate{cert})
	if err != nil {
		t.Fatal(err)
	}
	return s, cert
}

func TestSignKernel(t *testing.T) {
	signer, cert := testSigner(t)
	efi := ipxe.MustAsset("third_party/ipxe/src/bin-x86_64-efi/ipxe.efi")
	booter := fileBooter{kernel: "kernel", files: map[ID][]byte{
		"kernel":   efi,
		"other":    efi,
		"notefi":   []byte("not a UEFI image"),
		"notefiv2": []byte("MZ not a UEFI image either"),
	}}
	log := func(subsystem, msg string) { t.Logf("[%s] %s", subsystem, msg) }
	s := &Server{
		Booter:           booter,
		Log:              log,
		Debug:            log,
		SecureBootSigner: signer,
		events:           make(map[string][]machineEvent),
	}

	get := func(u string) []byte {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", u, nil)
		s.serveHTTPForTest(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s: HTTP %d", u, rr.Code)
		}
		if cl := rr.Header().Get("Content-Length"); cl != "" && cl != strconv.Itoa(rr.Body.Len()) {
			t.Fatalf("GET %s: Content-Length %s for %d bytes", u, cl, rr.Body.Len())
		}
		return rr.Body.Bytes()
	}
	signed := func(bs []byte) bool {
		t.Helper()
		ok, err := uefisign.Verify(bs, cert)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}

	// The kernel URL in the boot script fetches the kernel signed.
	script := get("/_/ipxe?mac=01:02:03:04:05:06&arch=1")
	m := regexp.MustCompile(`kernel --name kernel http://[^/]+(\S+)`).FindSubmatch(script)
	if m == nil {
		t.Fatalf("no kernel in boot script:\n%s", script)
	}
	if !signed(get(string(m[1]))) {
		t.Fatal("kernel from the boot script isn't signed")
	}

	// Other files aren't signed, even if asked for as a kernel, and
	// kernels are only signed for the machine they're for.
	mac, _ := net.ParseMAC("01:02:03:04:05:06")
	for _, u := range []string{
		"/_/file?name=kernel&type=kernel&mac=01:02:03:04:05:06",
		"/_/file?name=other&type=kernel&mac=01:02:03:04:05:06&ksig=" + s.kernelToken("kernel", mac),
		"/_/file?name=kernel&type=kernel&mac=01:02:03:04:05:07&ksig=" + s.kernelToken("kernel", mac),
		"/_/file?name=kernel&type=kernel&ksig=" + s.kernelToken("kernel", mac),
		"/_/file?name=kernel",
	} {
		if !bytes.Equal(get(u), efi) {
			t.Errorf("GET %s: file was changed", u)
		}
	}

	// Kernels that aren't UEFI images are served unsigned.
	for _, name := range []ID{"notefi", "notefiv2"} {
		u := "/_/file?type=kernel&mac=01:02:03:04:05:06&name=" + url.QueryEscape(string(name)) + "&ksig=" + s.kernelToken(name, mac)
		if got := get(u); !bytes.Equal(got, booter.files[name]) {
			t.Errorf("GET %s: got %q", u, got)
		}
	}
}

func (s *Server) serveHTTPForTest(w http.ResponseWriter, r *http.Request) {
	mux := http.NewServeMux()
	s.serveHTTP(mux)
	mux.ServeHTTP(w, r)
}
