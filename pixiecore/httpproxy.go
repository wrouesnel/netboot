package pixiecore

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"sync"
	"time"
)

const (
	// portHTTPProxy is the conventional HTTP proxy port, as used by
	// Squid.
	portHTTPProxy = 3128
	// httpProxyDialTimeout limits how long a proxied request waits for
	// the destination to accept the connection.
	httpProxyDialTimeout = 10 * time.Second
)

// serveHTTPProxy serves a forward HTTP proxy on l. CONNECT requests are
// tunnelled without interception, so TLS is end to end between the
// client and the destination. Plain HTTP requests are forwarded.
func (s *Server) serveHTTPProxy(l net.Listener) error {
	dialer := &net.Dialer{Timeout: httpProxyDialTimeout}
	forward := &httputil.ReverseProxy{
		// The request is already for the destination. Rewrite, unlike
		// Director, strips hop-by-hop headers such as
		// Proxy-Authorization and adds no X-Forwarded headers.
		Rewrite: func(r *httputil.ProxyRequest) {},
		Transport: &http.Transport{
			// Don't chain through Pixiecore's own proxy settings.
			Proxy:                 nil,
			DialContext:           dialer.DialContext,
			TLSHandshakeTimeout:   httpProxyDialTimeout,
			ResponseHeaderTimeout: time.Minute,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          100,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.log("HTTPProxy", "Failed to forward %s %s for %s: %s", r.Method, r.URL, r.RemoteAddr, err)
			http.Error(w, "proxy error", http.StatusBadGateway)
		},
	}
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				s.proxyConnect(w, r, dialer)
				return
			}
			if r.URL.Scheme != "http" || r.URL.Host == "" {
				http.Error(w, "only CONNECT and absolute http:// requests are proxied", http.StatusBadRequest)
				return
			}
			s.debug("HTTPProxy", "Forwarding %s %s for %s", r.Method, r.URL, r.RemoteAddr)
			forward.ServeHTTP(w, r)
		}),
		ReadHeaderTimeout: 30 * time.Second,
	}
	if err := srv.Serve(l); err != nil {
		return fmt.Errorf("HTTP proxy shut down: %s", err)
	}
	return nil
}

// proxyConnect tunnels a CONNECT request to its destination.
func (s *Server) proxyConnect(w http.ResponseWriter, r *http.Request, dialer *net.Dialer) {
	if _, _, err := net.SplitHostPort(r.Host); err != nil {
		http.Error(w, "CONNECT needs a host:port", http.StatusBadRequest)
		return
	}
	target, err := dialer.DialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		s.log("HTTPProxy", "Failed to connect %s to %s: %s", r.RemoteAddr, r.Host, err)
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}
	defer target.Close()

	conn, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		s.log("HTTPProxy", "Failed to take over the connection from %s: %s", r.RemoteAddr, err)
		http.Error(w, "proxy error", http.StatusInternalServerError)
		return
	}
	defer conn.Close()
	// The server's timeouts no longer apply once the tunnel is up.
	_ = conn.SetDeadline(time.Time{})
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	s.debug("HTTPProxy", "Tunnelling %s to %s", r.RemoteAddr, r.Host)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		// buf holds anything the client sent after the request, e.g.
		// the start of a TLS handshake.
		pipe(target, buf.Reader)
	}()
	go func() {
		defer wg.Done()
		pipe(conn, target)
	}()
	wg.Wait()
}

// pipe copies src to dst until src is done, then closes the write side
// of dst, so the far end sees EOF while the other direction continues.
func pipe(dst net.Conn, src io.Reader) {
	_, _ = io.Copy(dst, src)
	if c, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = c.CloseWrite()
	} else {
		dst.Close()
	}
}
