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

## Install a signed release artifact

For a production installation, download the archive matching your operating
system, its `.bundle` signature, and `enumscan-sha256sums.txt` from the same
tagged release. Verify the exact archive before extracting it:

```sh
VERSION=v1.2.3
ARCHIVE="enumscan-${VERSION}-linux-amd64.tar.gz"
cosign verify-blob --bundle "${ARCHIVE}.bundle" "${ARCHIVE}"
grep " ${ARCHIVE}$" enumscan-sha256sums.txt | sha256sum -c -
tar -xzf "${ARCHIVE}"
"enumscan-${VERSION}-linux-amd64/enumscan" help
```

Use the matching `darwin-arm64.tar.gz` archive on macOS or
`windows-amd64.zip` on Windows. Archives contain only the binary, a safe scan
template, authorized-use guidance, and release documentation.

On Windows, verify `enumscan-${VERSION}-windows-amd64.zip` with `cosign.exe`
and compare `Get-FileHash -Algorithm SHA256` output with the matching manifest
entry before extracting it with `Expand-Archive`.

Tagged releases also include verified package-manager artifacts:
- **Debian / Ubuntu**: `enumscan_<version>_amd64.deb`
  ```sh
  cosign verify-blob --bundle enumscan_<version>_amd64.deb.bundle enumscan_<version>_amd64.deb
  grep ' enumscan_<version>_amd64.deb$' enumscan-sha256sums.txt | sha256sum -c -
  sudo apt-get install ./enumscan_<version>_amd64.deb
  ```
- **Fedora / RHEL / CentOS**: `enumscan-<version>-1.x86_64.rpm`
  ```sh
  cosign verify-blob --bundle enumscan-<version>-1.x86_64.rpm.bundle enumscan-<version>-1.x86_64.rpm
  grep ' enumscan-<version>-1.x86_64.rpm$' enumscan-sha256sums.txt | sha256sum -c -
  sudo dnf install ./enumscan-<version>-1.x86_64.rpm
  ```
- **macOS Homebrew (ARM64)**: `enumscan-<version>-homebrew.rb`
  ```sh
  brew install --formula ./enumscan-<version>-homebrew.rb
  ```
- **Windows Scoop (AMD64)**: `enumscan-<version>-scoop.json`
  ```powershell
  scoop install ./enumscan-<version>-scoop.json
  ```

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

### Guided engagement setup

For a new repeatable engagement, use the wizard instead of editing a template
by hand. It requires a single IP address, CIDR, or hostname plus a written
authorization reference, then creates a new private configuration file. It
does not overwrite an existing file and enables safe enumeration only.

```sh
make engagement-wizard
make validate-config CONFIG=configs/engagement.yaml
```

The dashboard's **New engagement** button produces the same validated YAML as
a browser download. Review it and start the scan with the CLI; the dashboard
does not persist the new engagement or alter its server scope. Authenticated
dashboard deployments require an admin role to generate this plan.

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
