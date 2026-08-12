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

- SQLite uses a native Go driver with WAL mode, a busy timeout, and serialized pooled writes for reliable concurrent scan persistence.
- YAML support is intentionally constrained to the project config/template shapes in `configs/` and `templates/`.
- Port scanning supports quick, standard, and exhaustive profiles; explicit TCP/UDP port overrides; TCP banner grabbing; UDP response probes; and adaptive timeouts.
- Production builds expose verified TCP connect scanning only; raw-packet scan techniques are intentionally disabled pending a real packet implementation.
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
  max_concurrent_ports: 8
  record_closed_ports: false
  base_timeout_ms: 750
  max_timeout_ms: 3000
```

If `tcp_ports` or `udp_ports` is empty, `enumscan` expands the selected profile automatically. TCP scanning uses a bounded connect sweep followed by optional banner enrichment of confirmed open ports only. UDP scanning includes validated DNS, TFTP, RPCBind, NTP, NetBIOS, SNMP, IKE, RADIUS, SSDP, SIP, and mDNS probes where their ports are selected. Every confirmed open port is also retained in the `port_observations` history table.

`max_concurrent_ports` bounds per-host scan pressure. Keep `record_closed_ports` off unless the assessment requires closed/filtered state evidence, as it significantly increases stored data. Raw SYN/ACK/FIN/NULL/XMAS/idle/window/Maimon, fragmentation, and decoy techniques are intentionally unavailable in production builds until a privileged, explicitly authorized packet implementation exists.

## Discovery

Discovery is scope-checked and conservative by default. Set `discovery.enable_dns_discovery: true` to resolve a scoped domain and collect resolver-visible DNS context; `enable_dns_records` additionally collects TXT/SPF, DMARC, and common SRV records. Passive DNS, certificate-transparency, and tcpdump/tshark text exports can be imported through the configured file lists.

Active host liveness checks are individually opt-in: `enable_icmp_sweep` uses the platform ICMP utility, `enable_tcp_host_probes` uses TCP connect evidence (including connection refused), and `enable_udp_live_probes` sends protocol-valid DNS/NTP probes only. Timeouts are never reported as dead hosts. Raw SYN/ACK probing and live packet capture remain disabled in production builds because they need a separately authorized privileged-capture implementation.

## Service Fingerprinting

The `service_fingerprint` module subscribes to open-port events and combines port hints, captured banners, UDP responses, and small protocol probes. It currently recognizes common infrastructure services including SSH, FTP, SMTP, DNS, SMB, LDAP, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, Docker, Kubernetes, WinRM, RDP, NFS, VNC, and HTTP-family services.

Port-only identities are persisted as `heuristic`; evidence from a banner or an active protocol response is marked `observed`. The module also extracts versioned runtime evidence for OpenSSL, Python, Go, Java, Ruby, Node.js, Gunicorn, Werkzeug, and Jetty, with CPE 2.3 candidates. TCP/IP stack OS guesses are never fabricated from network ranges; they require real packet traits from an authorized collector and remain heuristic.

## HTTP, TLS, and Crawling

The HTTP module records response metadata, security-header findings, TLS certificates, SANs, supported TLS versions, negotiated ciphers, robots.txt and sitemap URLs, scoped crawl links, JavaScript endpoints, potential client-side secret hints, API discovery hits, and screenshot targets. Screenshot targets are queued as assets until a real browser renderer is added; no synthetic screenshot files are recorded as captures.

## Directory and API Enumeration

The optional `directory_api_enumerator` performs a bounded, scope-checked pass over common and technology-specific paths. It derives additional paths from first-party JavaScript, checks for exposed backups, Git/SVN metadata and environment files, and records OpenAPI, GraphQL, SOAP/WSDL and gRPC reflection evidence. Configure `http.max_directory_paths` and `http.directory_wordlist` to keep the request volume appropriate for the authorization you hold.

It also checks validated Mercurial metadata and common editor/backup temporary files. With `http.enable_source_map_analysis`, it parses scoped source maps without storing source content, records discovered endpoints, and sends only redacted secret fingerprints through the normal heuristic secret workflow. API endpoint responses are inspected for advertised rate-limit headers and JSON/OpenAPI schema shape; no unsafe API methods are sent.

## Container and Kubernetes Enumeration

When `specialized.enable_container` is enabled, the standard profile includes Docker, registry, etcd, Kubernetes API, and kubelet ports. The specialized module identifies exposed Docker API sockets, registries and runtime endpoints; validates exposed Compose files; and records Kubernetes secrets-list endpoint access with only an item count, never secret values.

The same explicit opt-in also identifies scoped Podman API and containerd HTTP health endpoints from real responses. Database enumeration identifies Cassandra, ClickHouse, InfluxDB, MSSQL, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, and Memcached protocol evidence without attempting passwords, privilege changes, or data extraction. LDAP RootDSE responses yield observed naming contexts without directory-object enumeration. SNMP checks require operator-supplied communities; no default community strings are guessed. HTTP response headers can also identify AWS Lambda, Azure Functions, and GCP Cloud Run/Functions endpoints.

## Passive Intelligence

Set `passive_intel.enabled: true` and choose sources in `passive_intel.sources` to enable third-party lookups. API credentials are read from environment variables (`SHODAN_API_KEY`, `CENSYS_API_ID`/`CENSYS_API_SECRET`, `SECURITYTRAILS_API_KEY`, `FOFA_EMAIL`/`FOFA_API_KEY`, `VIRUSTOTAL_API_KEY`, `GITHUB_TOKEN`, and `GITLAB_TOKEN`), not YAML. Supported source names are `shodan`, `censys`, `securitytrails`, `fofa`, `virustotal`, `wayback`, `github`, `gitlab`, `bucket`, and `paste`. `paste` requires `PASTE_MONITOR_URL`; GitLab accepts `GITLAB_API_URL` for self-hosted instances.

## Secret Intelligence

HTTP content can be scanned for AWS, Azure, GCP, JWT, generic API, and private-key indicators with `http.enable_secret_intelligence`. Findings use structural validation and risk scoring locally; discovered values are represented only by a redacted, hashed fingerprint and are never sent to a validation service or persisted in clear text.

## Vulnerability Prioritization

Run `analyze-vulnerabilities <scan-id>` after importing vulnerability reports and current intelligence feeds. It correlates feed-provided KEV, EPSS, and public-exploit indicators, records a priority asset for every CVE finding, and applies built-in misconfiguration rules to discovered assets. Original findings are preserved unchanged for auditability.

## Intelligence Quality Controls

NVD imports accept `-version` and `-provenance` and record a checksum and fetch time for feed traceability. Heuristic findings are explicitly labeled in reports, while reviewed false positives can be suppressed through the `vulnerability.ReviewWorkflow` API using a stable finding fingerprint. Secret evidence is retained only as redacted findings and evidence hashes; the scanner never validates credentials against external services.

## Evidence Correlation

Run `correlate <scan-id>` to build a graph from collected asset parents, trust/authentication evidence, secret exposures, lateral-movement-capable services, and findings. It persists inferred correlation edges, a 0–100 business-impact score, and a Mermaid attack-chain representation. Inferred edges identify possible relationships, not confirmed attacker access.

## Risk Scoring

Run `score-risk <scan-id>` to produce explainable 0–100 composite risk assessments. Scores combine internet exposure, asset criticality, business-context clues, finding severity, EPSS, KEV, and curated public-exploit indicators. Each assessment includes its contributing factors in metadata.

## Differential Analysis

Run `compare-scans <baseline-scan-id> <current-scan-id>` to generate a Markdown change report. It compares host, port, service, certificate, technology, and vulnerability evidence; a removed item means it was not observed in the current scan.

## Automation

Modules automatically chain by emitting events for later subscribers. An `asset.changed` event triggers scoped re-enumeration of the affected host or URL. The engine also exposes `RunRecurring(ctx, interval)` for programmatic recurring scans, creating a fresh scan ID for every scheduled run.

## Operator Console

Start the local API with `go run ./cmd/enumscan -config configs/example.yaml server` and open `http://127.0.0.1:8080/`. The dashboard provides scan health/progress, asset and relationship explorers, an event timeline, server-side asset/finding search, saved queries, and a dark/light theme. It refreshes scan state every five seconds. The screenshot gallery shows only verified `screenshot` artifacts; queued targets and unavailable captures are deliberately not displayed as evidence.
