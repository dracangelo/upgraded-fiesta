# enumscan

`enumscan` is a CLI-first reconnaissance framework for authorized security assessments. It is structured as an event-driven pipeline: modules discover assets, publish events, persist scan state, and feed later modules such as HTTP enumeration and reporting.

This first scaffold focuses on the core engine, scheduler, networking, crawling-ready HTTP enumeration, SQLite storage, YAML configuration/templates, reporting, and Python scripting hooks.

## Safety Model

Only scan systems you are explicitly authorized to assess. `enumscan` requires targets to match the configured scope before modules run.

## Quick Start

```bash
go run ./cmd/enumscan -config configs/example.yaml init-db
go run ./cmd/enumscan -config configs/example.yaml run example-scan
go run ./cmd/enumscan -config configs/example.yaml report example-scan -format markdown
```

Reports are written to `reports/`. Scan state is stored in SQLite at the path configured in YAML.

## Project Shape

```text
cmd/enumscan          CLI entrypoint
internal/config      Constrained YAML configuration loader
internal/engine      Event-driven scan engine
internal/modules     Discovery, port scanning, and HTTP enumeration modules
internal/scheduler   Work queue and module orchestration
internal/scope       Authorization scope enforcement
internal/store       SQLite-backed persistence via sqlite3 CLI
internal/reporting   JSON and Markdown reports
templates            YAML scan templates
configs              Local scan configuration
scripts              Python utility scripts
plugins              Plugin examples and future SDK surface
```

## Notes

- SQLite is accessed through the installed `sqlite3` command to keep this scaffold dependency-free.
- YAML support is intentionally constrained to the project config/template shapes in `configs/` and `templates/`.
- Port scanning supports quick, standard, and exhaustive profiles; explicit TCP/UDP port overrides; TCP banner grabbing; UDP response probes; and adaptive timeouts.
- Service fingerprinting normalizes open-port evidence into `service`, `service_version`, and `cpe_candidate` assets for later vulnerability correlation.
- Raw SYN packet scanning, advanced TLS tests, AD/SMB enumeration, and vulnerability correlation are planned in `todo.md`.

## Port Scanning

Configure port scanning in `configs/example.yaml`:

```yaml
portscan:
  profile: "quick" # quick, standard, exhaustive
  tcp_ports: [80, 443, 8080]
  udp_ports: [53, 123, 161]
  enable_tcp: true
  enable_udp: true
  enable_banner: true
  base_timeout_ms: 750
  max_timeout_ms: 3000
```

If `tcp_ports` or `udp_ports` is empty, `enumscan` expands the selected profile automatically. Use the exhaustive profile only inside tightly authorized scope with conservative rate limits.

## Service Fingerprinting

The `service_fingerprint` module subscribes to open-port events and combines port hints, captured banners, UDP responses, and small protocol probes. It currently recognizes common infrastructure services including SSH, FTP, SMTP, DNS, SMB, LDAP, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Docker, Kubernetes, WinRM, RDP, NFS, VNC, and HTTP-family services.

## HTTP, TLS, and Crawling

The HTTP module records response metadata, security-header findings, TLS certificates, SANs, supported TLS versions, negotiated ciphers, robots.txt and sitemap URLs, scoped crawl links, JavaScript endpoints, potential client-side secret hints, API discovery hits, and screenshot targets. Screenshot targets are queued as assets until a browser renderer such as Playwright or Chromedp is added.

## Directory and API Enumeration

The optional `directory_api_enumerator` performs a bounded, scope-checked pass over common and technology-specific paths. It derives additional paths from first-party JavaScript, checks for exposed backups, Git/SVN metadata and environment files, and records OpenAPI, GraphQL, SOAP/WSDL and gRPC reflection evidence. Configure `http.max_directory_paths` and `http.directory_wordlist` to keep the request volume appropriate for the authorization you hold.

## Container and Kubernetes Enumeration

When `specialized.enable_container` is enabled, the standard profile includes Docker, registry, etcd, Kubernetes API, and kubelet ports. The specialized module identifies exposed Docker API sockets, registries and runtime endpoints; validates exposed Compose files; and records Kubernetes secrets-list endpoint access with only an item count, never secret values.

## Passive Intelligence

Set `passive_intel.enabled: true` and choose sources in `passive_intel.sources` to enable third-party lookups. API credentials are read from environment variables (`SHODAN_API_KEY`, `CENSYS_API_ID`/`CENSYS_API_SECRET`, `SECURITYTRAILS_API_KEY`, `FOFA_EMAIL`/`FOFA_API_KEY`, `VIRUSTOTAL_API_KEY`, `GITHUB_TOKEN`, and `GITLAB_TOKEN`), not YAML. Supported source names are `shodan`, `censys`, `securitytrails`, `fofa`, `virustotal`, `wayback`, `github`, `gitlab`, `bucket`, and `paste`. `paste` requires `PASTE_MONITOR_URL`; GitLab accepts `GITLAB_API_URL` for self-hosted instances.

## Secret Intelligence

HTTP content can be scanned for AWS, Azure, GCP, JWT, generic API, and private-key indicators with `http.enable_secret_intelligence`. Findings use structural validation and risk scoring locally; discovered values are represented only by a redacted, hashed fingerprint and are never sent to a validation service or persisted in clear text.

## Vulnerability Prioritization

Run `analyze-vulnerabilities <scan-id>` after importing vulnerability reports. It correlates locally maintained KEV, EPSS, and public-exploit indicators, records a priority asset for every CVE finding, and applies built-in misconfiguration rules to discovered assets. Original findings are preserved unchanged for auditability.

## Evidence Correlation

Run `correlate <scan-id>` to build a graph from collected asset parents, trust/authentication evidence, secret exposures, lateral-movement-capable services, and findings. It persists inferred correlation edges, a 0–100 business-impact score, and a Mermaid attack-chain representation. Inferred edges identify possible relationships, not confirmed attacker access.
