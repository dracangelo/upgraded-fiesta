# Getting started

Enumscan is a Go-based, event-driven reconnaissance platform for authorized
security assessments. It stores evidence locally, supports repeatable scan
profiles, and produces reports without asserting exploitation or compromise.

## Prerequisites

- Go 1.25 or newer.
- Network access from the scanner to the authorized targets.
- Optional: Docker, PostgreSQL, Neo4j, a browser wrapper, or provider API
  credentials for their corresponding features.

## Build and verify

```sh
make build
make test
```

The binary is written to `dist/enumscan`. For development, every command can
also be run with `go run ./cmd/enumscan`.

## Create a configuration

```sh
make scan-templates
make new-scan-config TEMPLATE=web OUTPUT_CONFIG=configs/my-scan.yaml
```

Edit `configs/my-scan.yaml` and replace the target, authorization reference,
database path, and any feature-specific placeholders. Never commit an
engagement configuration containing target or credential metadata.

Use `make scan-template` if you prefer the comprehensive general-purpose
template instead of an assessment-specific starting point.

For a guided IP/CIDR scan:

```sh
make interactive-scan
```

## Run a scan

```sh
make init-db CONFIG=configs/my-scan.yaml
make scan CONFIG=configs/my-scan.yaml SCAN_ID=engagement-001
```

Scan IDs should be unique and meaningful. The engine rejects targets outside
`scope.allowed_targets` before modules run.

## Generate a report

```sh
make report CONFIG=configs/my-scan.yaml SCAN_ID=engagement-001 FORMAT=markdown
```

Other formats include `json`, `executive`, `technical`, `triage`, `html`,
`pdf`, `sarif`, `csv`, and `neo4j`.

## Open the operator interfaces

```sh
make dashboard CONFIG=configs/my-scan.yaml
make tui CONFIG=configs/my-scan.yaml
```

The dashboard listens on loopback by default. Configure API authentication and
TLS before exposing it beyond the local operator workstation.

## Next steps

- Choose a profile and tune bounds in [Configuration](configuration.md).
- Understand module behavior in [Scanning and modules](scanning.md).
- Configure production storage in [Operations](operations.md).
- Review the [Security model](security.md) before enabling outbound,
  authenticated, raw-socket, or active functionality.
