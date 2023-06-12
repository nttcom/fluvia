# Getting Started with Fluvia Exporter

This page explains how to export IPFIX with Fluvia Exporter.

## Instllation

```bash
$ go install github.com/nttcom/fluvia/cmd/fluvia@latest
```

## Configuration

Specify the IP address and port number for IPFIX collector

```yaml
---
ipfix:
  addr: 127.0.0.1
  port: 4739
```

## Run Fluvia Exporter using the fluvia command

Start the fluvia command. Specify the created configuration file with the -f option.

```bash
$ sudo fluvia -f fluvia.yaml
```
