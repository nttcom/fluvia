# Getting Started with Fluvia Exporter

This page explains how to export IPFIX with Fluvia Exporter.

## 1. Fluvia Exporter as a IPFIX Exporter Daemon
### Instllation

```bash
$ go install github.com/nttcom/fluvia/cmd/fluvia@latest
```

### Configuration

Specify the IP address and port number for IPFIX collector

```yaml
---
ipfix:
  addr: 192.0.2.1
  port: 4739
```

### Run Fluvia Exporter using the fluvia command

Start the fluvia command. Specify the created configuration file with the -f option.

```bash
$ sudo fluvia -f fluvia.yaml
```

> **Note**
> TODO: Implement `meter.go` to acquire flow data and send it to `exporter.go` via channel ch.
> Currently, the fluvia command only has an exporter function, and `meter.go` is not implemented yet.


## 2. Fluvia Exporter as a Native IPFIX Exporter Library
### Clone this repository

```bash
$ git clone https://github.com/nttcom/fluvia
```

### Run the example tools

`tools/exporter/exporter.go` is an example of Fluvia Exporter as a native IPFIX exporter library.
This code includes the IPFIX templates/data from [draft-ietf-opsawg-ipfix-srv6-srh](https://datatracker.ietf.org/doc/draft-ietf-opsawg-ipfix-srv6-srh/) Appendix A Figure 1/2.

```
$ cd tools/exporter
$ go run exporter.go
```
