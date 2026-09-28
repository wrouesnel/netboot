# Netboot, packages and utilities for network booting

[![Build and Test](https://github.com/wrouesnel/netboot/actions/workflows/integration.yml/badge.svg)](https://github.com/wrouesnel/netboot/actions/workflows/integration.yml)

This repository contains Go implementations of network protocols used
in booting machines over the network, as well as utilites built on top
of these libraries.

This is a fork of [danderson/netboot](https://github.com/danderson/netboot), which is
no longer actively developed. The fork tracks upstream and exists to implement
additional features and fixes on top of it.

## Programs

- [Pixiecore](pixiecore/): Command line all-in-one tool for easy netbooting

## Libraries

The canonical import path for Go packages in this repository is `github.com/wrouesnel/netboot`.
Upstream uses `go.universe.tf/netboot`; code moving from upstream to this fork needs its
imports updated.

- [pcap](https://pkg.go.dev/github.com/wrouesnel/netboot/pcap): Pure Go implementation of reading and writing pcap files.
- [dhcp4](https://pkg.go.dev/github.com/wrouesnel/netboot/dhcp4): DHCPv4 library providing the low-level bits of a DHCP client/server (packet marshaling, RFC-compliant packet transmission semantics).
- [tftp](https://pkg.go.dev/github.com/wrouesnel/netboot/tftp): Read-only TFTP server implementation.
- [pixiecore](https://pkg.go.dev/github.com/wrouesnel/netboot/pixiecore): Go library for Pixiecore tool functionality. Every stability warning in this repository applies double for this package.

