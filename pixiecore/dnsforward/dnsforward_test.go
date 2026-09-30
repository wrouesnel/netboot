package dnsforward

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func TestParseUpstream(t *testing.T) {
	cases := []struct {
		spec, want string
		wantErr    bool
	}{
		{spec: "192.0.2.53", want: "192.0.2.53:53"},
		{spec: "192.0.2.53:5353", want: "192.0.2.53:5353"},
		{spec: "2001:db8::53", want: "[2001:db8::53]:53"},
		{spec: "[2001:db8::53]:5353", want: "[2001:db8::53]:5353"},
		{spec: "https://1.1.1.1/dns-query", want: "https://1.1.1.1/dns-query"},
		{spec: "https://dns.example/dns-query?x=1", want: "https://dns.example/dns-query?x=1"},
		{spec: "", wantErr: true},
		{spec: "dns.example", wantErr: true},
		{spec: "192.0.2.53:0", wantErr: true},
		{spec: "192.0.2.53:dns", wantErr: true},
		{spec: "http://dns.example/dns-query", wantErr: true},
		{spec: "tls://192.0.2.53", wantErr: true},
		{spec: "https:///dns-query", wantErr: true},
	}
	for _, tc := range cases {
		u, err := ParseUpstream(tc.spec)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseUpstream(%q) = %s, want error", tc.spec, u)
			}
			continue
		}
		if err != nil || u.String() != tc.want {
			t.Errorf("ParseUpstream(%q) = %v, %v; want %s", tc.spec, u, err, tc.want)
		}
	}
}

func TestParseOverride(t *testing.T) {
	self := net.ParseIP("192.0.2.1")
	cases := []struct {
		spec     string
		self     net.IP
		wantName string
		wantIP   string
		wantErr  bool
	}{
		{spec: "api.example", self: self, wantName: "api.example.", wantIP: "192.0.2.1"},
		{spec: "API.Example.", self: self, wantName: "api.example.", wantIP: "192.0.2.1"},
		{spec: "*.example", self: self, wantName: "*.example.", wantIP: "192.0.2.1"},
		{spec: "api.example=192.0.2.9", self: self, wantName: "api.example.", wantIP: "192.0.2.9"},
		{spec: "api.example=2001:db8::9", wantName: "api.example.", wantIP: "2001:db8::9"},
		{spec: "api.example", wantErr: true},
		{spec: "api.example=nope", self: self, wantErr: true},
		{spec: "", self: self, wantErr: true},
		{spec: ".", self: self, wantErr: true},
		{spec: "a.*.example", self: self, wantErr: true},
		{spec: "api..example", self: self, wantErr: true},
	}
	for _, tc := range cases {
		o, err := ParseOverride(tc.spec, tc.self)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ParseOverride(%q) = %+v, want error", tc.spec, o)
			}
			continue
		}
		if err != nil || o.Name != tc.wantName || o.IP.String() != tc.wantIP {
			t.Errorf("ParseOverride(%q) = %+v, %v; want %s %s", tc.spec, o, err, tc.wantName, tc.wantIP)
		}
	}
}

// serveDNS serves h on loopback UDP and TCP, on the same port.
func serveDNS(t *testing.T, h dns.Handler) string {
	t.Helper()
	for {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("tcp", pc.LocalAddr().String())
		if err != nil {
			pc.Close()
			continue
		}
		for _, srv := range []*dns.Server{{PacketConn: pc, Handler: h}, {Listener: l, Handler: h}} {
			started := make(chan struct{})
			srv.NotifyStartedFunc = func() { close(started) }
			go func() { _ = srv.ActivateAndServe() }()
			<-started
			t.Cleanup(func() { _ = srv.Shutdown() })
		}
		return pc.LocalAddr().String()
	}
}

// upstream answers A queries with 198.51.100.1, TXT queries for
// big.example with a long answer, and names under fail.example with
// SERVFAIL.
var upstream = dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
	resp := new(dns.Msg).SetReply(req)
	q := req.Question[0]
	switch {
	case strings.HasSuffix(q.Name, "fail.example."):
		resp.Rcode = dns.RcodeServerFailure
	case q.Qtype == dns.TypeA:
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("198.51.100.1"),
		})
	case q.Qtype == dns.TypeTXT && q.Name == "big.example.":
		for i := 0; i < 20; i++ {
			resp.Answer = append(resp.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{strings.Repeat("x", 100)},
			})
		}
	}
	_, udp := w.RemoteAddr().(*net.UDPAddr)
	if udp {
		resp.Truncate(dns.MinMsgSize)
	}
	_ = w.WriteMsg(resp)
})

// goodUpstream answers A queries with ip.
func goodUpstream(ip string) dns.HandlerFunc {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg).SetReply(req)
		q := req.Question[0]
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP(ip),
		})
		_ = w.WriteMsg(resp)
	}
}

func query(t *testing.T, network, addr, name string, qtype uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg).SetQuestion(name, qtype)
	resp, _, err := (&dns.Client{Net: network}).Exchange(req, addr)
	if err != nil {
		t.Fatalf("%s %s %s: %s", network, name, dns.TypeToString[qtype], err)
	}
	if resp.Id != req.Id {
		t.Errorf("%s %s: response ID %d, want %d", network, name, resp.Id, req.Id)
	}
	return resp
}

func answers(resp *dns.Msg) []string {
	var ret []string
	for _, rr := range resp.Answer {
		switch rr := rr.(type) {
		case *dns.A:
			ret = append(ret, rr.A.String())
		case *dns.AAAA:
			ret = append(ret, rr.AAAA.String())
		default:
			ret = append(ret, dns.TypeToString[rr.Header().Rrtype])
		}
	}
	return ret
}

func mustOverride(t *testing.T, spec string, self net.IP) Override {
	t.Helper()
	o, err := ParseOverride(spec, self)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestForwarder(t *testing.T) {
	up, err := ParseUpstream(serveDNS(t, upstream))
	if err != nil {
		t.Fatal(err)
	}
	self := net.ParseIP("192.0.2.1")
	f := &Forwarder{
		Upstreams: []Upstream{up},
		Overrides: []Override{
			mustOverride(t, "api.example", self),
			mustOverride(t, "*.boot.example", self),
			mustOverride(t, "dual.example=192.0.2.2", nil),
			mustOverride(t, "dual.example=2001:db8::2", nil),
		},
		Log: t.Logf,
	}
	addr := serveDNS(t, f)

	cases := []struct {
		name  string
		qtype uint16
		want  string
	}{
		{"www.example.", dns.TypeA, "198.51.100.1"},
		{"api.example.", dns.TypeA, "192.0.2.1"},
		{"API.EXAMPLE.", dns.TypeA, "192.0.2.1"},
		// Overridden names only have the overridden addresses.
		{"api.example.", dns.TypeAAAA, ""},
		{"api.example.", dns.TypeMX, ""},
		{"a.boot.example.", dns.TypeA, "192.0.2.1"},
		{"a.b.boot.example.", dns.TypeA, "192.0.2.1"},
		// The wildcard doesn't match the domain itself.
		{"boot.example.", dns.TypeA, "198.51.100.1"},
		{"dual.example.", dns.TypeA, "192.0.2.2"},
		{"dual.example.", dns.TypeAAAA, "2001:db8::2"},
		{"dual.example.", dns.TypeANY, "192.0.2.2 2001:db8::2"},
	}
	for _, network := range []string{"udp", "tcp"} {
		for _, tc := range cases {
			resp := query(t, network, addr, tc.name, tc.qtype)
			if got := strings.Join(answers(resp), " "); resp.Rcode != dns.RcodeSuccess || got != tc.want {
				t.Errorf("%s %s %s: got %s %q, want %q", network, tc.name, dns.TypeToString[tc.qtype], dns.RcodeToString[resp.Rcode], got, tc.want)
			}
		}
	}

	// A big answer is fetched from the upstream over TCP, then
	// truncated over UDP so the client retries over TCP.
	if resp := query(t, "udp", addr, "big.example.", dns.TypeTXT); !resp.Truncated {
		t.Errorf("udp big.example: not truncated, %d answers", len(resp.Answer))
	}
	if resp := query(t, "tcp", addr, "big.example.", dns.TypeTXT); resp.Truncated || len(resp.Answer) != 20 {
		t.Errorf("tcp big.example: truncated=%v, %d answers, want 20", resp.Truncated, len(resp.Answer))
	}
	// EDNS0 clients get as much as their buffer allows.
	req := new(dns.Msg).SetQuestion("big.example.", dns.TypeTXT).SetEdns0(4096, false)
	if resp, _, err := (&dns.Client{Net: "udp", UDPSize: 4096}).Exchange(req, addr); err != nil || resp.Truncated || len(resp.Answer) != 20 {
		t.Errorf("udp EDNS0 big.example: %v, want 20 answers untruncated", err)
	}
}

func TestForwarderFailover(t *testing.T) {
	down, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	downAddr := down.LocalAddr().String()
	down.Close()
	var ups []Upstream
	for _, spec := range []string{downAddr, serveDNS(t, upstream), serveDNS(t, goodUpstream("198.51.100.2"))} {
		u, err := ParseUpstream(spec)
		if err != nil {
			t.Fatal(err)
		}
		ups = append(ups, u)
	}

	// An unreachable upstream is skipped.
	addr := serveDNS(t, &Forwarder{Upstreams: ups[:2], Log: t.Logf})
	if got := answers(query(t, "udp", addr, "www.example.", dns.TypeA)); len(got) != 1 || got[0] != "198.51.100.1" {
		t.Errorf("got %q, want the second upstream's answer", got)
	}
	// SERVFAIL tries the next upstream, and is returned if none
	// answers.
	if resp := query(t, "udp", addr, "x.fail.example.", dns.TypeA); resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("got %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
	addr = serveDNS(t, &Forwarder{Upstreams: ups, Log: t.Logf})
	if got := answers(query(t, "udp", addr, "x.fail.example.", dns.TypeA)); len(got) != 1 || got[0] != "198.51.100.2" {
		t.Errorf("got %q, want the third upstream's answer", got)
	}
	// No upstream answers.
	addr = serveDNS(t, &Forwarder{Upstreams: ups[:1], Log: t.Logf})
	if resp := query(t, "udp", addr, "www.example.", dns.TypeA); resp.Rcode != dns.RcodeServerFailure {
		t.Errorf("got %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
}

func TestDoH(t *testing.T) {
	var gotIDs []uint16
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/dns-query" || r.Header.Get("Content-Type") != dohContentType {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		body, _ := io.ReadAll(r.Body)
		req := &dns.Msg{}
		if err := req.Unpack(body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		gotIDs = append(gotIDs, req.Id)
		resp := new(dns.Msg).SetReply(req)
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("198.51.100.3"),
		})
		bs, _ := resp.Pack()
		w.Header().Set("Content-Type", dohContentType)
		_, _ = w.Write(bs)
	}))
	defer srv.Close()

	newUpstream := func(path string) Upstream {
		u, err := ParseUpstream(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		u.(*dohUpstream).client = srv.Client()
		return u
	}

	addr := serveDNS(t, &Forwarder{Upstreams: []Upstream{newUpstream("/dns-query")}, Log: t.Logf})
	for _, network := range []string{"udp", "tcp"} {
		if got := answers(query(t, network, addr, "www.example.", dns.TypeA)); len(got) != 1 || got[0] != "198.51.100.3" {
			t.Errorf("%s: got %q", network, got)
		}
	}
	// RFC 8484 section 4.1.
	for _, id := range gotIDs {
		if id != 0 {
			t.Errorf("DoH query had ID %d, want 0", id)
		}
	}

	// HTTP errors fail the upstream.
	if _, err := newUpstream("/wrong").Exchange(context.Background(), new(dns.Msg).SetQuestion("www.example.", dns.TypeA)); err == nil {
		t.Error("want an error from a 400 response")
	}
	// Untrusted certificates fail the upstream.
	u, _ := ParseUpstream(srv.URL + "/dns-query")
	if _, err := u.Exchange(context.Background(), new(dns.Msg).SetQuestion("www.example.", dns.TypeA)); err == nil {
		t.Error("want an error from an untrusted DoH server")
	}
}
