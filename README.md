<p align="center">
<img src="https://github.com/nttcom/fluvia/blob/main/docs/figures/fluvia.png" alt="Fluvia Exporter" width="15%">
</p>

# Fluvia Exporter

[![Linter](https://github.com/nttcom/fluvia/actions/workflows/ci.yml/badge.svg)](https://github.com/nttcom/fluvia/actions)
[![Releaser](https://github.com/nttcom/fluvia/actions/workflows/release.yml/badge.svg)](https://github.com/nttcom/fluvia/actions)
[![Go Report Card](https://goreportcard.com/badge/nttcom/fluvia)](https://goreportcard.com/report/github.com/nttcom/fluvia) 
[![Go Reference](https://pkg.go.dev/badge/github.com/nttcom/fluvia.svg)](https://pkg.go.dev/github.com/nttcom/fluvia)
[![Go version](https://img.shields.io/github/go-mod/go-version/nttcom/fluvia)](https://go.dev/)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

IPFIX Exporter using eBPF/XDP and IPFIX Library in Go

## Features
* IPFIX Exporter in XDP/eBPF-enabled Environments
* Support for IANA Reserved Information Elements (IEs)
    * [IP Flow Information Export (IPFIX) Entities](https://www.iana.org/assignments/ipfix/ipfix.xhtml)

## Installation & Use
* [Getting Started](docs/sources/getting-started.md)

## Contributing
If you are interested in contributing to the project, please refer to the [CONTRIBUTING](https://github.com/nttcom/fluvia/blob/main/CONTRIBUTING.md) guidelines.  
Feel free to fork the repository and create a Pull Request. Your contributions are highly appreciated.

## Licensing
Fluvia Exporter is licensed under the [MIT license](https://en.wikipedia.org/wiki/MIT_License).  
For the full license text, see [LICENSE](https://github.com/nttcom/fluvia/blob/master/LICENSE).

## Miscellaneous
Fluvia Exporter supports the following IETF Internet-Drafts:
- [Export of Segment Routing over IPv6 Information in IP Flow Information Export (IPFIX)](https://datatracker.ietf.org/doc/html/draft-ietf-opsawg-ipfix-srv6-srh-14)
  - IPFIX Library: Supports all IEs.
  - IPFIX Exporter: Implemented the following IEs.
    - srhActiveSegmentIPv6
    - srhSegmentsIPv6Left
    - srhFlagsIPv6
    - srhTagIPv6
    - srhSegmentIPv6BasicList
