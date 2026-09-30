// Package dnsforward implements a forwarding DNS server, which answers
// some names itself and forwards other queries to upstream DNS or
// DNS-over-HTTPS (RFC 8484) servers.
package dnsforward

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	// overrideTTL is the TTL of override answers.
	overrideTTL = 60
	// upstreamTimeout limits each upstream query.
	upstreamTimeout = 5 * time.Second
	// maxDoHResponse limits the size of DNS-over-HTTPS responses.
	maxDoHResponse = 64 << 10
	dohContentType = "application/dns-message"
)

// An Upstream answers DNS queries.
type Upstream interface {
	Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error)
	String() string
}

// ParseUpstream parses an upstream server, which is an IP address with
// an optional port (53 by default), e.g. "192.0.2.53",
// "[2001:db8::53]:5353", or an https:// DNS-over-HTTPS URL, e.g.
// "https://1.1.1.1/dns-query".
func ParseUpstream(s string) (Upstream, error) {
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return nil, fmt.Errorf("DNS upstream %q isn't an IP address or https:// URL", s)
		}
		return &dohUpstream{url: u.String(), client: &http.Client{Timeout: upstreamTimeout}}, nil
	}
	host, port := s, "53"
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("DNS upstream %q isn't an IP address or https:// URL", s)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, fmt.Errorf("DNS upstream %q: port %q isn't a number from 1 to 65535", s, port)
	}
	return &dnsUpstream{addr: net.JoinHostPort(ip.String(), port)}, nil
}

// dnsUpstream is a plain DNS server, queried over UDP, and over TCP if
// the answer is truncated.
type dnsUpstream struct {
	addr string
}

func (u *dnsUpstream) String() string { return u.addr }

func (u *dnsUpstream) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	resp, _, err := (&dns.Client{Net: "udp", Timeout: upstreamTimeout}).ExchangeContext(ctx, req, u.addr)
	if err == nil && resp.Truncated {
		resp, _, err = (&dns.Client{Net: "tcp", Timeout: upstreamTimeout}).ExchangeContext(ctx, req, u.addr)
	}
	return resp, err
}

// dohUpstream is a DNS-over-HTTPS server.
type dohUpstream struct {
	url    string
	client *http.Client
}

func (u *dohUpstream) String() string { return u.url }

func (u *dohUpstream) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	// RFC 8484 section 4.1: use ID 0, for caching.
	q := req.Copy()
	q.Id = 0
	body, err := q.Pack()
	if err != nil {
		return nil, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	hreq.Header.Set("Content-Type", dohContentType)
	hreq.Header.Set("Accept", dohContentType)
	hresp, err := u.client.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s", hresp.Status)
	}
	if ct := hresp.Header.Get("Content-Type"); ct != dohContentType {
		return nil, fmt.Errorf("unexpected Content-Type %q", ct)
	}
	bs, err := io.ReadAll(io.LimitReader(hresp.Body, maxDoHResponse+1))
	if err != nil {
		return nil, err
	}
	if len(bs) > maxDoHResponse {
		return nil, errors.New("response too large")
	}
	resp := &dns.Msg{}
	if err := resp.Unpack(bs); err != nil {
		return nil, err
	}
	resp.Id = req.Id
	return resp, nil
}

// An Override answers A and AAAA queries for a name with fixed
// addresses, instead of forwarding them.
type Override struct {
	// Name is a domain name, or "*.domain" for every name under domain
	// (but not domain itself).
	Name string
	IP   net.IP
}

// ParseOverride parses an override, which is "name=ip", or just "name"
// to answer with self. Names can start with "*." to match every name
// under a domain.
func ParseOverride(s string, self net.IP) (Override, error) {
	name, ipStr, hasIP := strings.Cut(s, "=")
	o := Override{Name: dns.CanonicalName(name), IP: self}
	if hasIP {
		if o.IP = net.ParseIP(ipStr); o.IP == nil {
			return Override{}, fmt.Errorf("DNS override %q: %q isn't an IP address", s, ipStr)
		}
	} else if self == nil {
		return Override{}, fmt.Errorf("DNS override %q: no address to answer with", s)
	}
	check := strings.TrimPrefix(o.Name, "*.")
	if _, ok := dns.IsDomainName(check); !ok || check == "." || strings.Contains(check, "*") {
		return Override{}, fmt.Errorf("DNS override %q: %q isn't a domain name", s, name)
	}
	return o, nil
}

func (o Override) matches(name string) bool {
	if suffix, ok := strings.CutPrefix(o.Name, "*"); ok {
		return strings.HasSuffix(name, suffix) && len(name) > len(suffix)
	}
	return name == o.Name
}

// A Forwarder is a dns.Handler that answers queries for Overrides
// itself, and forwards other queries to Upstreams.
type Forwarder struct {
	// Upstreams are tried in order until one answers.
	Upstreams []Upstream
	Overrides []Override

	// Log and Debug receive logs, if set.
	Log   func(format string, args ...any)
	Debug func(format string, args ...any)
}

// ServeDNS implements dns.Handler.
func (f *Forwarder) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	resp := f.answer(req)
	// UDP answers must fit the client's buffer. Truncation sets the TC
	// bit, so the client retries over TCP.
	if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
		size := dns.MinMsgSize
		if opt := req.IsEdns0(); opt != nil {
			size = max(int(opt.UDPSize()), dns.MinMsgSize)
		}
		resp.Truncate(size)
	}
	if err := w.WriteMsg(resp); err != nil {
		f.debug("Failed to answer %s: %s", w.RemoteAddr(), err)
	}
}

func (f *Forwarder) answer(req *dns.Msg) *dns.Msg {
	if req.Opcode != dns.OpcodeQuery || len(req.Question) != 1 {
		return new(dns.Msg).SetRcode(req, dns.RcodeNotImplemented)
	}
	q := req.Question[0]
	if resp := f.override(req, q); resp != nil {
		return resp
	}

	ctx, cancel := context.WithTimeout(context.Background(), upstreamTimeout*time.Duration(max(len(f.Upstreams), 1)))
	defer cancel()
	var last *dns.Msg
	for _, u := range f.Upstreams {
		resp, err := u.Exchange(ctx, req)
		if err != nil {
			f.log("Failed to query %s for %s %s: %s", u, q.Name, dns.TypeToString[q.Qtype], err)
			continue
		}
		f.debug("Forwarded %s %s to %s: %s", q.Name, dns.TypeToString[q.Qtype], u, dns.RcodeToString[resp.Rcode])
		resp.Id = req.Id
		// A broken or unwilling upstream: try the next one.
		if resp.Rcode == dns.RcodeServerFailure || resp.Rcode == dns.RcodeRefused {
			last = resp
			continue
		}
		return resp
	}
	if last != nil {
		return last
	}
	return new(dns.Msg).SetRcode(req, dns.RcodeServerFailure)
}

// override answers q if it's for an overridden name. Pixiecore is
// authoritative for those names, so other query types get an empty
// answer rather than being forwarded.
func (f *Forwarder) override(req *dns.Msg, q dns.Question) *dns.Msg {
	name := dns.CanonicalName(q.Name)
	var resp *dns.Msg
	for _, o := range f.Overrides {
		if !o.matches(name) {
			continue
		}
		if resp == nil {
			resp = new(dns.Msg).SetReply(req)
			resp.Authoritative = true
			resp.RecursionAvailable = true
		}
		if q.Qclass != dns.ClassINET {
			continue
		}
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Ttl: overrideTTL}
		if ip4 := o.IP.To4(); ip4 != nil {
			if q.Qtype == dns.TypeA || q.Qtype == dns.TypeANY {
				hdr.Rrtype = dns.TypeA
				resp.Answer = append(resp.Answer, &dns.A{Hdr: hdr, A: ip4})
			}
		} else if q.Qtype == dns.TypeAAAA || q.Qtype == dns.TypeANY {
			hdr.Rrtype = dns.TypeAAAA
			resp.Answer = append(resp.Answer, &dns.AAAA{Hdr: hdr, AAAA: o.IP})
		}
	}
	if resp != nil {
		f.debug("Answered %s %s with %d overrides", q.Name, dns.TypeToString[q.Qtype], len(resp.Answer))
	}
	return resp
}

func (f *Forwarder) log(format string, args ...any) {
	if f.Log != nil {
		f.Log(format, args...)
	}
}

func (f *Forwarder) debug(format string, args ...any) {
	if f.Debug != nil {
		f.Debug(format, args...)
	}
}
