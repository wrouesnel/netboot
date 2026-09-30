// Copyright © 2016 David Anderson <dave@natulte.net>
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

package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/wrouesnel/netboot/pixiecore"
)

var apiCmd = &cobra.Command{
	Use:   "api server",
	Short: "Boot machines using instructions from one or more API servers",
	Long: `API mode is a "PXE to HTTP" translator. Whenever Pixiecore sees a
machine trying to PXE boot, it will ask a remote HTTP(S) API server
what to do. The API server can tell Pixiecore to ignore the machine,
or tell it what to boot.

It is your responsibility to implement or run a server that implements
the Pixiecore boot API. The specification can be found in
pixiecore/README.api.md.

HTTPS API servers can be authenticated with --api-ca-cert, and
Pixiecore can authenticate itself to the API server with HTTP basic
auth (--api-username), a client certificate (--api-client-cert), or a
client certificate whose key is held in the system TPM
(--tpm-enabled --api-client-tpm, see "pixiecore tpm-cert").

--http-proxy serves an HTTP proxy on --http-proxy-port, e.g. so
machines on the subnet Pixiecore manages can reach the API server
through it. CONNECT requests, and so TLS, are tunnelled without being
intercepted. The port is sent to the API server in the
` + pixiecore.HeaderPixiecoreProxyPort + ` header.

--dns serves DNS on --dns-port, forwarding queries to --dns-upstream
servers, which can be DNS-over-HTTPS. --dns-override names are answered
with Pixiecore's address. The address is sent to the API server in the
` + pixiecore.HeaderPixiecoreDNS + ` header.`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			fatalf("you must specify an API URL")
		}
		server := args[0]

		booter, err := pixiecore.APIBooterWithClient(server, apiClientFromFlags(cmd, server))
		if err != nil {
			fatalf("Failed to create API booter: %s", err)
		}
		s := serverFromFlags(cmd)
		s.Booter = booter
		if s.HTTPProxy, err = cmd.Flags().GetBool("http-proxy"); err != nil {
			fatalf("Error reading flag: %s", err)
		}
		if s.HTTPProxyPort, err = cmd.Flags().GetInt("http-proxy-port"); err != nil {
			fatalf("Error reading flag: %s", err)
		}
		dnsFromFlags(cmd, s, server)

		fmt.Println(s.Serve())
	}}

func init() {
	rootCmd.AddCommand(apiCmd)
	serverConfigFlags(apiCmd)
	apiClientFlags(apiCmd)
	apiCmd.Flags().Bool("http-proxy", false, "Serve an HTTP proxy, which tunnels CONNECT requests without intercepting them. The port is sent to the API server in the "+pixiecore.HeaderPixiecoreProxyPort+" header")
	apiCmd.Flags().Int("http-proxy-port", 3128, "Port to listen on for the HTTP proxy, with --http-proxy")
	dnsFlags(apiCmd)
}
