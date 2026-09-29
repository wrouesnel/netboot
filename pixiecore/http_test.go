// Copyright 2016 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pixiecore

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/wrouesnel/netboot/version"
)

type booterFunc func(Machine) (*Spec, error)

func (b booterFunc) BootSpec(m Machine) (*Spec, error) { return b(m) }
func (b booterFunc) ReadBootFile(id ID) (io.ReadCloser, int64, error) {
	return nil, -1, errors.New("no")
}
func (b booterFunc) WriteBootFile(id ID, r io.Reader) error { return errors.New("no") }

func TestIpxe(t *testing.T) {
	booter := func(m Machine) (*Spec, error) {
		return &Spec{
			Kernel: ID(fmt.Sprintf("k-%s-%d", m.MAC, m.Arch)),
			Initrd: []ID{
				ID(fmt.Sprintf("i1-%s-%d", m.MAC, m.Arch)),
				ID(fmt.Sprintf("i2-%s-%d", m.MAC, m.Arch)),
			},
			Cmdline: fmt.Sprintf(`thing={{ ID "f-%s-%d" }} foo=bar`, m.MAC, m.Arch),
			Message: "Hello from the test!",
		}, nil
	}
	log := func(subsystem, msg string) { t.Logf("[%s] %s", subsystem, msg) }
	s := &Server{
		Booter: booterFunc(booter),
		Log:    log,
		Debug:  log,
		events: make(map[string][]machineEvent),
	}

	// Successful boot
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/_/ipxe?mac=01:02:03:04:05:06&arch=0", nil)
	if err != nil {
		t.Fatalf("Constructing ipxe request: %s", err)
	}
	req.Host = "localhost:1234"
	s.handleIpxe(rr, req)

	if rr.Code != 200 {
		t.Fatalf("Got HTTP %d from request, expected 200", rr.Code)
	}

	expected := `#!ipxe
kernel --name kernel http://localhost:1234/_/file?name=k-01%3A02%3A03%3A04%3A05%3A06-0&type=kernel&mac=01%3A02%3A03%3A04%3A05%3A06
initrd --name initrd0 http://localhost:1234/_/file?name=i1-01%3A02%3A03%3A04%3A05%3A06-0&type=initrd&mac=01%3A02%3A03%3A04%3A05%3A06
initrd --name initrd1 http://localhost:1234/_/file?name=i2-01%3A02%3A03%3A04%3A05%3A06-0&type=initrd&mac=01%3A02%3A03%3A04%3A05%3A06
imgfetch --name ready http://localhost:1234/_/booting?mac=01%3A02%3A03%3A04%3A05%3A06 ||
imgfree ready ||
boot kernel initrd=initrd0 initrd=initrd1 thing=http://localhost:1234/_/file?name=f-01%3A02%3A03%3A04%3A05%3A06-0 foo=bar
`
	if rr.Body.String() != expected {
		t.Fatalf("Wrong iPXE script\nwant: %s\ngot:  %s", expected, rr.Body.String())
	}

	// Another successful boot
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/_/ipxe?mac=fe:fe:fe:fe:fe:fe&arch=1", nil)
	if err != nil {
		t.Fatalf("Constructing ipxe request: %s", err)
	}
	req.Host = "localhost:1234"
	s.handleIpxe(rr, req)

	if rr.Code != 200 {
		t.Fatalf("Got HTTP %d from request, expected 200", rr.Code)
	}

	expected = `#!ipxe
kernel --name kernel http://localhost:1234/_/file?name=k-fe%3Afe%3Afe%3Afe%3Afe%3Afe-1&type=kernel&mac=fe%3Afe%3Afe%3Afe%3Afe%3Afe
initrd --name initrd0 http://localhost:1234/_/file?name=i1-fe%3Afe%3Afe%3Afe%3Afe%3Afe-1&type=initrd&mac=fe%3Afe%3Afe%3Afe%3Afe%3Afe
initrd --name initrd1 http://localhost:1234/_/file?name=i2-fe%3Afe%3Afe%3Afe%3Afe%3Afe-1&type=initrd&mac=fe%3Afe%3Afe%3Afe%3Afe%3Afe
imgfetch --name ready http://localhost:1234/_/booting?mac=fe%3Afe%3Afe%3Afe%3Afe%3Afe ||
imgfree ready ||
boot kernel initrd=initrd0 initrd=initrd1 thing=http://localhost:1234/_/file?name=f-fe%3Afe%3Afe%3Afe%3Afe%3Afe-1 foo=bar
`
	if rr.Body.String() != expected {
		t.Fatalf("Wrong iPXE script\nwant: %s\ngot:  %s", expected, rr.Body.String())
	}

	// Invalid requests
	for _, url := range []string{
		"/_/ipxe?mac=any&arch=1",
		"/_/ipxe?mac=fe:fe:fe:fe:fe:fe&arch=x86",
		"/_/ipxe?mac=fe:fe:fe:fe:fe:fe&arch=42",
	} {
		rr = httptest.NewRecorder()
		req, err = http.NewRequest("GET", url, nil)
		if err != nil {
			t.Fatalf("Constructing ipxe request: %s", err)
		}
		s.handleIpxe(rr, req)

		if rr.Code != 400 {
			t.Fatalf("Got HTTP %d from request, expected 400", rr.Code)
		}
	}

	// Refused boot (no error)
	booter = func(m Machine) (*Spec, error) { return nil, nil }
	s.Booter = booterFunc(booter)
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/_/ipxe?mac=fe:fe:fe:fe:fe:fe&arch=1", nil)
	if err != nil {
		t.Fatalf("Constructing ipxe request: %s", err)
	}
	s.handleIpxe(rr, req)

	if rr.Code != 404 {
		t.Fatalf("Got HTTP %d from request, expected 404", rr.Code)
	}

	// Booter error
	booter = func(m Machine) (*Spec, error) { return nil, errors.New("boom") }
	s.Booter = booterFunc(booter)
	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/_/ipxe?mac=fe:fe:fe:fe:fe:fe&arch=1", nil)
	if err != nil {
		t.Fatalf("Constructing ipxe request: %s", err)
	}
	s.handleIpxe(rr, req)

	if rr.Code != 500 {
		t.Fatalf("Got HTTP %d from request, expected 500", rr.Code)
	}
}

type readBootFile string

func (b readBootFile) BootSpec(m Machine) (*Spec, error) { return nil, nil }
func (b readBootFile) ReadBootFile(id ID) (io.ReadCloser, int64, error) {
	d := fmt.Sprintf("%s %s", id, b)
	return io.NopCloser(bytes.NewBuffer([]byte(d))), int64(len(d)), nil
}
func (b readBootFile) WriteBootFile(id ID, r io.Reader) error { return errors.New("no") }

func TestFile(t *testing.T) {
	log := func(subsystem, msg string) { t.Logf("[%s] %s", subsystem, msg) }
	s := &Server{
		Booter: readBootFile("stuff"),
		Log:    log,
		Debug:  log,
	}
	rr := httptest.NewRecorder()
	req, err := http.NewRequest("GET", "/_/file?name=test", nil)
	if err != nil {
		t.Fatalf("Constructing file request: %s", err)
	}
	s.handleFile(rr, req)

	if rr.Code != 200 {
		t.Fatalf("Got HTTP %d from request, expected 200", rr.Code)
	}

	expected := "test stuff"
	if rr.Body.String() != expected {
		t.Fatalf("Wrong file contents, want %q, got %q", expected, rr.Body.Bytes())
	}

	rr = httptest.NewRecorder()
	req, err = http.NewRequest("GET", "/_/file?name=quux", nil)
	if err != nil {
		t.Fatalf("Constructing file request: %s", err)
	}
	s.handleFile(rr, req)

	if rr.Code != 200 {
		t.Fatalf("Got HTTP %d from request, expected 200", rr.Code)
	}

	expected = "quux stuff"
	if rr.Body.String() != expected {
		t.Fatalf("Wrong file contents, want %q, got %q", expected, rr.Body.Bytes())
	}
}

func TestVersion(t *testing.T) {
	s := &Server{}
	mux := http.NewServeMux()
	s.serveHTTP(mux)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("GET", "/version", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /version: status %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("GET /version: Content-Type %q", ct)
	}
	var got map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("GET /version: invalid JSON %q: %s", rr.Body, err)
	}
	if want := map[string]string{"version": version.Version}; !reflect.DeepEqual(got, want) {
		t.Errorf("GET /version = %v, want %v", got, want)
	}

	rr = httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest("POST", "/version", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /version: status %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestIpxeHTTPS(t *testing.T) {
	booter := func(m Machine) (*Spec, error) {
		return &Spec{Kernel: "k", Cmdline: `f={{ ID "f" }}`}, nil
	}
	s := &Server{Booter: booterFunc(booter), events: make(map[string][]machineEvent)}

	// A script requested over HTTPS refers to files over HTTPS.
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/_/ipxe?mac=01:02:03:04:05:06&arch=0", nil)
	req.Host = "pixiecore.example:8443"
	req.TLS = &tls.ConnectionState{}
	s.handleIpxe(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("Got HTTP %d, want 200", rr.Code)
	}
	if got, want := strings.Count(rr.Body.String(), "https://pixiecore.example:8443/_/"), 3; got != want {
		t.Errorf("script has %d HTTPS URLs, want %d:\n%s", got, want, rr.Body)
	}
	if strings.Contains(rr.Body.String(), "http://") {
		t.Errorf("script has HTTP URLs:\n%s", rr.Body)
	}
}

func TestHTTPBaseURL(t *testing.T) {
	ip := net.ParseIP("192.0.2.1")
	for _, tc := range []struct {
		s    *Server
		want string
	}{
		{&Server{HTTPPort: 80}, "http://192.0.2.1:80"},
		{&Server{HTTPPort: 80, HTTPSPort: 443, TLSConfig: &tls.Config{}}, "https://192.0.2.1:443"},
		{&Server{HTTPPort: 80, HTTPSPort: 8443, TLSConfig: &tls.Config{}, HTTPHost: "pixiecore.example"}, "https://pixiecore.example:8443"},
		{&Server{HTTPPort: 8080, HTTPHost: "pixiecore.example"}, "http://pixiecore.example:8080"},
	} {
		if got := tc.s.httpBaseURL(ip); got != tc.want {
			t.Errorf("httpBaseURL = %q, want %q", got, tc.want)
		}
	}
}
