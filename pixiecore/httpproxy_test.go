package pixiecore

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// startHTTPProxy serves the HTTP proxy on a loopback port, returning its
// URL.
func startHTTPProxy(t *testing.T) *url.URL {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{}
	done := make(chan error, 1)
	go func() { done <- s.serveHTTPProxy(l) }()
	t.Cleanup(func() {
		l.Close()
		if err := <-done; err == nil {
			t.Error("serveHTTPProxy returned nil after the listener closed")
		}
	})
	return &url.URL{Scheme: "http", Host: l.Addr().String()}
}

func TestHTTPProxyConnect(t *testing.T) {
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "hello over %s", r.Proto)
	}))
	defer origin.Close()
	proxy := startHTTPProxy(t)

	// The client only trusts the origin's certificate, so this also
	// checks the proxy doesn't intercept TLS.
	transport := origin.Client().Transport.(*http.Transport).Clone()
	transport.Proxy = http.ProxyURL(proxy)
	client := &http.Client{Transport: transport}
	for i := 0; i < 3; i++ {
		resp, err := client.Get(origin.URL)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.TLS == nil || !resp.TLS.PeerCertificates[0].Equal(origin.Certificate()) {
			t.Error("TLS connection wasn't to the origin")
		}
		if resp.StatusCode != http.StatusOK || !strings.HasPrefix(string(body), "hello over HTTP/") {
			t.Errorf("got %d %q", resp.StatusCode, body)
		}
		transport.CloseIdleConnections()
	}
}

func TestHTTPProxyConnectEarlyData(t *testing.T) {
	// Clients may send the TLS handshake straight after CONNECT without
	// waiting for the response, so it's buffered with the request.
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()
	proxy := startHTTPProxy(t)

	conn, err := net.Dial("tcp", proxy.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	host := strings.TrimPrefix(origin.URL, "https://")
	// httptest's certificate is for example.com.
	cfg := origin.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	cfg.ServerName = "example.com"
	tlsConn := tls.Client(&connectConn{Conn: conn, request: "CONNECT " + host + " HTTP/1.1\r\nHost: " + host + "\r\n\r\n"}, cfg)
	if _, err := io.WriteString(tlsConn, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Errorf("got %q", body)
	}
}

// connectConn sends the CONNECT request in the same write as the first
// data, and strips the proxy's response from what's read.
type connectConn struct {
	net.Conn
	request string
	br      *bufio.Reader
}

func (c *connectConn) Write(b []byte) (int, error) {
	if c.request != "" {
		req := c.request
		c.request = ""
		if _, err := c.Conn.Write(append([]byte(req), b...)); err != nil {
			return 0, err
		}
		return len(b), nil
	}
	return c.Conn.Write(b)
}

func (c *connectConn) Read(b []byte) (int, error) {
	if c.br == nil {
		c.br = bufio.NewReader(c.Conn)
		resp, err := http.ReadResponse(c.br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			return 0, err
		}
		if resp.StatusCode != http.StatusOK {
			return 0, fmt.Errorf("CONNECT: %s", resp.Status)
		}
	}
	return c.br.Read(b)
}

func TestHTTPProxyForward(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s auth=%q", r.Method, r.URL.Path, r.Header.Get("Proxy-Authorization"))
	}))
	defer origin.Close()
	proxy := startHTTPProxy(t)

	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	req, _ := http.NewRequest(http.MethodGet, origin.URL+"/foo", nil)
	req.Header.Set("Proxy-Authorization", "Basic c2VjcmV0")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// Proxy-Authorization is for the proxy, not the origin.
	if want := `GET /foo auth=""`; resp.StatusCode != http.StatusOK || string(body) != want {
		t.Errorf("got %d %q, want %q", resp.StatusCode, body, want)
	}
}

func TestHTTPProxyErrors(t *testing.T) {
	proxy := startHTTPProxy(t)
	down, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	downAddr := down.Addr().String()
	down.Close()

	cases := []struct {
		request string
		want    int
	}{
		// Not a proxy request.
		{"GET /foo HTTP/1.1\r\nHost: example\r\n\r\n", http.StatusBadRequest},
		{"GET https://" + downAddr + "/ HTTP/1.1\r\nHost: " + downAddr + "\r\n\r\n", http.StatusBadRequest},
		{"CONNECT example HTTP/1.1\r\nHost: example\r\n\r\n", http.StatusBadRequest},
		{"CONNECT " + downAddr + " HTTP/1.1\r\nHost: " + downAddr + "\r\n\r\n", http.StatusBadGateway},
		{"GET http://" + downAddr + "/ HTTP/1.1\r\nHost: " + downAddr + "\r\n\r\n", http.StatusBadGateway},
	}
	for _, tc := range cases {
		conn, err := net.Dial("tcp", proxy.Host)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(conn, tc.request); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		conn.Close()
		if err != nil {
			t.Errorf("%q: %s", tc.request, err)
			continue
		}
		if resp.StatusCode != tc.want {
			t.Errorf("%q: got %s, want %d", tc.request, resp.Status, tc.want)
		}
	}
}
