package cli

import (
	"fmt"
	"net"
	"os"

	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/wrouesnel/netboot/pixiecore"
	"github.com/wrouesnel/netboot/pixiecore/dnsforward"
)

// resolvConf is where the default DNS upstreams come from.
var resolvConf = "/etc/resolv.conf"

// dnsFlags adds the DNS forwarder flags.
func dnsFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("dns", false, "Serve DNS, forwarding queries to --dns-upstream. The address is sent to the API server in the "+pixiecore.HeaderPixiecoreDNS+" header")
	cmd.Flags().Int("dns-port", 53, "Port to listen on for DNS, with --dns")
	cmd.Flags().StringArray("dns-upstream", nil, "DNS server to forward queries to, as an IP address with an optional port, or an https:// DNS-over-HTTPS URL. Can be repeated, and they're tried in order (default: the nameservers in "+resolvConf+")")
	cmd.Flags().StringArray("dns-override", nil, "Answer queries for a name with Pixiecore's IP address, or name=ip for another address. *.domain matches every name under domain. Can be repeated")
}

// dnsFromFlags sets up s.DNSForwarder, if --dns is given.
func dnsFromFlags(cmd *cobra.Command, s *pixiecore.Server, apiURL string) {
	enabled, err := cmd.Flags().GetBool("dns")
	if err != nil {
		fatalf("Error reading flag: %s", err)
	}
	upstreams, err := cmd.Flags().GetStringArray("dns-upstream")
	if err != nil {
		fatalf("Error reading flag: %s", err)
	}
	overrides, err := cmd.Flags().GetStringArray("dns-override")
	if err != nil {
		fatalf("Error reading flag: %s", err)
	}
	if !enabled {
		for _, name := range []string{"dns-port", "dns-upstream", "dns-override"} {
			if cmd.Flags().Changed(name) {
				fatalf("--%s requires --dns", name)
			}
		}
		return
	}
	if s.DNSPort, err = cmd.Flags().GetInt("dns-port"); err != nil {
		fatalf("Error reading flag: %s", err)
	}
	if s.DNSPort < 1 || s.DNSPort > 65535 {
		fatalf("--dns-port %d isn't a port number", s.DNSPort)
	}

	f := &dnsforward.Forwarder{}
	if len(upstreams) == 0 {
		conf, err := dns.ClientConfigFromFile(resolvConf)
		if err != nil || len(conf.Servers) == 0 {
			fatalf("No DNS upstreams: set --dns-upstream (couldn't read nameservers from %s: %v)", resolvConf, err)
		}
		for _, server := range conf.Servers {
			upstreams = append(upstreams, net.JoinHostPort(server, conf.Port))
		}
	}
	for _, spec := range upstreams {
		u, err := dnsforward.ParseUpstream(spec)
		if err != nil {
			fatalf("Invalid --dns-upstream: %s", err)
		}
		f.Upstreams = append(f.Upstreams, u)
	}

	if len(overrides) > 0 {
		self, err := pixiecoreIP(cmd, apiURL)
		if err != nil {
			fatalf("%s", err)
		}
		for _, spec := range overrides {
			o, err := dnsforward.ParseOverride(spec, self)
			if err != nil {
				fatalf("Invalid --dns-override: %s", err)
			}
			f.Overrides = append(f.Overrides, o)
		}
	}
	s.DNSForwarder = f
	fmt.Fprintf(os.Stderr, "Serving DNS on port %d, forwarding to %v with %d overrides\n", s.DNSPort, f.Upstreams, len(f.Overrides))
}
