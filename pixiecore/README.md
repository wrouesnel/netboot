# Pixiecore

Pixiecore is an tool to manage network booting of machines. It can be used
for simple single shot network boots, or as a building block of machine
management infrastructure.

[![license](https://img.shields.io/github/license/wrouesnel/netboot.svg)](https://github.com/wrouesnel/netboot/blob/main/LICENSE) ![api](https://img.shields.io/badge/api-unstable-red.svg) ![cli](https://img.shields.io/badge/cli-stable-green.svg) [![cli](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/github.com/wrouesnel/netboot/pixiecore)

## TL;DR

    pixiecore quick xyz --dhcp-no-bind

Then try to boot another machine from the same network.

## Why?

Booting a Linux system over the network is quite tedious. You have to
set up a TFTP server, reconfigure your DHCP server to recognize PXE
clients, and send them the right set of magical options to get them to
boot, often fighting rubbish PXE ROM implementations.

Pixiecore aims to simplify this process, by packing the whole process
into a single binary that can cooperate with your network's existing
DHCP server. You don't need to reconfigure anything else in the
network.

If you're curious about the whole process that Pixiecore manages, you
can read the details in [README.booting](README.booting.md).

## Installation

These installation methods track this fork. Upstream's Debian packages
and Docker Hub/Quay images are built from
[danderson/netboot](https://github.com/danderson/netboot) and do not
include this fork's changes.

### Go install

Build the latest Pixiecore via `go install`:

```shell
go install github.com/wrouesnel/netboot/cmd/pixiecore@latest
```

### Release binaries

Statically linked binaries for each tagged version are attached to the
[GitHub releases](https://github.com/wrouesnel/netboot/releases).

### Container images

Container images for `linux/amd64` and `linux/arm64` are published to
[ghcr.io/wrouesnel/netboot](https://github.com/wrouesnel/netboot/pkgs/container/netboot)
from the `main` branch (`latest`) and from version tags.

## Using Pixiecore in static mode ("I just want to boot a machine")

Run the pixiecore binary, passing it a kernel and initrd, and
optionally some extra kernel commandline arguments. For example,
here's how you make all machines in your network netboot into the
alpha release of CoreOS, with automatic login:

```shell
sudo pixiecore boot \
  https://alpha.release.core-os.net/amd64-usr/current/coreos_production_pxe.vmlinuz \
  https://alpha.release.core-os.net/amd64-usr/current/coreos_production_pxe_image.cpio.gz \
  --cmdline='coreos.autologin'
```

That's it! Any machine that tries to boot from the network will now
boot into CoreOS.

That's a bit slow to boot, because Pixiecore is refetching the images
from core-os.net each time a machine tries to boot. We can also
download the files and use those:

```shell
wget https://alpha.release.core-os.net/amd64-usr/current/coreos_production_pxe.vmlinuz
wget https://alpha.release.core-os.net/amd64-usr/current/coreos_production_pxe_image.cpio.gz
sudo pixiecore boot \
  coreos_production_pxe.vmlinuz \
  coreos_production_pxe_image.cpio.gz \
  --cmdline='coreos.autologin'
```

Sometimes, you want to give extra files to the booting OS. For
example, CoreOS lets you pass a Cloud Init file via the
`cloud-config-url` kernel commandline parameter. That's fine if you
have a URL, but what if you have a local file?

For this, Pixiecore lets you specify that you want an additional file
served over HTTP to the booting OS, via a template function. Let's
grab a [cloud-config.yml](https://goo.gl/7HzZf2) that sets the
hostname to `pixiecore-test`, and serve it:

```shell
wget -O my-cloud-config.yml https://goo.gl/7HzZf2
sudo pixiecore boot \
  coreos_production_pxe.vmlinuz \
  coreos_production_pxe_image.cpio.gz \
  --cmdline='coreos.autologin cloud-config-url={{ ID "./my-cloud-config.yml" }}'
```

Pixiecore will transform the template invocation into a URL that, when
fetched, serves `my-cloud-config.yml`. Similarly to the kernel and
initrd arguments, you can also pass a URL to the `ID` template
function.

## Pixiecore in API mode

Think of Pixiecore in API mode as a "PXE to HTTP" translator. Whenever
Pixiecore sees a machine trying to netboot, it will ask a remote HTTP
API (which you implement) what to do. The API server can tell
Pixiecore to ignore the machine, or tell it to boot into a given
kernel/initrd/commandline.

Effectively, Pixiecore in API mode lets you pretend that your machines
speak a simple JSON protocol when trying to netboot. This makes it
_far_ easier to play with netbooting in your own software.

To start Pixiecore in API mode, pass it the URL of your API endpoint:

```shell
sudo pixiecore api https://foo.example/pixiecore
```

The endpoint you provide must implement the Pixiecore boot API, as
described in the [API spec](README.api.md).

The API can be served over HTTPS, and Pixiecore can authenticate to it
with HTTP basic auth, a client certificate, or a client certificate
whose key is held in the system TPM. See
[Securing the API](README.api.md#securing-the-api).

Pixiecore logs its version when it starts, and its HTTP(S) servers
report it at `/version`, e.g. `{"version":"v1.2.3"}`.

You can find a sample API server implementation in the `api-example`
subdirectory. The code is not production-grade, but gives a short
illustration of how the protocol works by reimplementing a subset of
Pixiecore's static mode as an API server.

## Booting over HTTPS

Once iPXE is running, it fetches the boot script, kernel and initrds
from Pixiecore over HTTP. To use HTTPS instead, give Pixiecore a
certificate and key:

```shell
sudo pixiecore boot kernel initrd \
    --http-tls-cert /etc/pixiecore/chain.pem \
    --http-tls-key /etc/pixiecore/key.pem \
    --http-disabled
```

- HTTPS is served on `--https-port` (443 by default). Machines are
  booted over HTTPS when it's enabled. HTTP stays available on `--port`
  unless you pass `--http-disabled`, and one or the other must be
  enabled.
- By default machines reach Pixiecore at its IP address, so the
  certificate needs that IP address as a subject alternative name. To
  use a host name instead, set `--http-host`.
- Kernels and initrds that Pixiecore proxies are served over HTTPS too,
  as are URLs made by the `ID` template function in the kernel
  commandline, so the booted OS must also trust the certificate.

iPXE doesn't use the system's CA certificates. It trusts a certificate
chain if the chain ends at a certificate whose SHA-256 fingerprint is
built into it, and Pixiecore's iPXE binaries are built trusting the
iPXE project's root CA. So Pixiecore rewrites that list in the iPXE
binaries it serves, to trust the last certificate in `--http-tls-cert`.
Put your CA certificate at the end of the file (or use a self-signed
certificate). To trust more certificates, for example for HTTPS servers
a custom `ipxe-script` fetches from, add
`--ipxe-trust-cert ca.pem`. These replace the built-in list, up to 8
certificates. The servers must send chains ending at a trusted
certificate.

Only the UEFI iPXE binaries can be rewritten. The BIOS binaries are
compressed, so they only trust the certificates they were built with,
and Pixiecore warns about this at startup. To boot BIOS machines over
HTTPS with your own CA, build Pixiecore with the CA built in:

```shell
MAGE_IPXE_TRUST=/path/to/ca.pem go run mage.go updateIpxe binary
```

`MAGE_IPXE_TRUST` is a comma-separated list of PEM files. The iPXE
config Pixiecore builds with is in [ipxe-config](ipxe-config), which
enables HTTPS for BIOS builds.

HTTPS protects the boot after iPXE starts. iPXE itself is still loaded
over TFTP without any authentication.

## Running in containers

Because Pixiecore needs to listen for DHCP traffic, it has to run with
access to the host's networking stack, which Docker provides with the
`--net=host` commandline flag.

```shell
sudo docker run \
  --net=host \
  -v .:/image \
  ghcr.io/wrouesnel/netboot \
    boot /image/coreos_production_pxe.vmlinuz /image/coreos_production_pxe_image.cpio.gz
```

## Demos and users

Pixiecore was used alongside
[waitron](https://github.com/jhaals/waitron) in a
[presentation](https://youtu.be/QyGHZ2HCwqY?t=440) at the OpenStack
summit in 2016.

If you use Pixiecore, we'd love to hear about it, and know more about
how you're using it. You can open a pull request to be added to this
list, file an issue for me to add you, or just email me at
dave(at)natulte.net if you'd like to give feedback privately.

- [waitron](https://github.com/jhaals/waitron) uses Pixiecore to
  manage automated server installation based on machine templates.
