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
