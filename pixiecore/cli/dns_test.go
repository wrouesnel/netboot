package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/wrouesnel/netboot/pixiecore"
)

func TestDNSFromFlags(t *testing.T) {
	dir := t.TempDir()
	conf := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(conf, []byte("nameserver 192.0.2.53\nnameserver 2001:db8::53\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer func(old string) { resolvConf = old }(resolvConf)
	resolvConf = conf

	cases := []struct {
		args          []string
		wantPort      int
		wantUpstreams string
		wantOverrides string
	}{
		{args: []string{"--dns"}, wantPort: 53, wantUpstreams: "192.0.2.53:53 [2001:db8::53]:53"},
		{
			args:          []string{"--dns", "--dns-port", "5353", "--dns-upstream", "https://1.1.1.1/dns-query", "--dns-upstream", "192.0.2.54"},
			wantPort:      5353,
			wantUpstreams: "https://1.1.1.1/dns-query 192.0.2.54:53",
		},
		{
			args:          []string{"--dns", "--dns-override", "api.example", "--dns-override", "*.boot.example=192.0.2.9"},
			wantPort:      53,
			wantUpstreams: "192.0.2.53:53 [2001:db8::53]:53",
			wantOverrides: "api.example.=192.0.2.1 *.boot.example.=192.0.2.9",
		},
	}
	for _, tc := range cases {
		cmd := &cobra.Command{}
		serverConfigFlags(cmd)
		apiClientFlags(cmd)
		dnsFlags(cmd)
		if err := cmd.ParseFlags(append([]string{"--api-pixiecore-ip", "192.0.2.1"}, tc.args...)); err != nil {
			t.Fatal(err)
		}
		s := &pixiecore.Server{}
		dnsFromFlags(cmd, s, "http://127.0.0.1:8080")
		if s.DNSForwarder == nil {
			t.Fatalf("%q: no DNS forwarder", tc.args)
		}
		var upstreams, overrides []string
		for _, u := range s.DNSForwarder.Upstreams {
			upstreams = append(upstreams, u.String())
		}
		for _, o := range s.DNSForwarder.Overrides {
			overrides = append(overrides, o.Name+"="+o.IP.String())
		}
		if s.DNSPort != tc.wantPort || strings.Join(upstreams, " ") != tc.wantUpstreams || strings.Join(overrides, " ") != tc.wantOverrides {
			t.Errorf("%q: got port %d, upstreams %q, overrides %q", tc.args, s.DNSPort, upstreams, overrides)
		}
	}

	cmd := &cobra.Command{}
	serverConfigFlags(cmd)
	apiClientFlags(cmd)
	dnsFlags(cmd)
	s := &pixiecore.Server{}
	dnsFromFlags(cmd, s, "http://127.0.0.1:8080")
	if s.DNSForwarder != nil {
		t.Error("DNS forwarder set up without --dns")
	}
}
