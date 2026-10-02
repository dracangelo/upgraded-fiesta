# CLI reference

General form:

```text
enumscan -config <configuration.yaml> <command> [arguments]
```

## Workflow Groups & Commands

### 1. First-Run & Engagement Setup

| Command | Purpose |
| --- | --- |
| `engagement-wizard [-target target] [-template template] [-authorization ref] [-output path] [-yes]` | Interactive first-run wizard: validates scope and prerequisites, checks database writability, displays effective-plan preview with duration/probe estimates, and creates private mode-`0600` scope-locked configuration upon explicit operator confirmation. |
| `init-db` | Initialize or migrate the configured datastore |
| `validate-config [-format text\|json]` | Offline validation and effective execution-plan preflight |
| `capabilities [-format text\|json\|markdown]` | Report authoritative feature status without loading a scan configuration |
| `doctor [-remote] [-format text\|json]` | Validate provider configuration; `-remote` performs explicit bounded provider calls |

Supported assessment templates for `engagement-wizard`:
- `standard`: General Infrastructure Enumeration (host, port, service, banner, and web discovery)
- `web`: Web Application & Surface Discovery (crawling, JS analysis, API endpoints, TLS)
- `network`: Internal Network & Infrastructure (service, banner, protocol capabilities)
- `api`: API & Microservice Assessment (REST, GraphQL, OpenAPI metadata)
- `external`: External Perimeter Reconnaissance (DNS record harvest, external perimeter)
- `cloud`: Cloud Exposure & Asset Mapping (cloud endpoints, certificates, exposure mapping)
- `all`: All Scan Types (Exhaustive full-surface enumeration across all safe modules)

### 2. Scan Execution & Monitoring

| Command | Purpose |
| --- | --- |
| `run <scan-id>` | Run one scope-validated scan |
| `monitor [-prefix name]` | Run the configured bounded monitoring schedule |
| `server [-port 8080]` | Start the local API, dashboard, and SSE/WS stream server |

## Analyze and report

| Command | Purpose |
| --- | --- |
| `report <scan-id> -format <format>` | Generate a report from stored evidence |
| `analyze-vulnerabilities <scan-id>` | Correlate findings with imported intelligence |
| `score-risk <scan-id>` | Calculate deterministic risk scores |
| `correlate <scan-id>` | Build exposure relationships and attack-path narratives |
| `compare-scans <baseline> <current>` | Produce differential results |
| `local-llm-summary <scan-id>` | Request an advisory from a configured loopback Ollama service |
| `sync-neo4j <scan-id>` | Explicitly synchronize evidence to configured Neo4j |

## Import

```sh
enumscan -config configs/my-scan.yaml import-report scan-001 \
  -tool nuclei -file findings.json
enumscan -config configs/my-scan.yaml import-nvd -file nvd-delta.json
enumscan -config configs/my-scan.yaml git-secrets repo-001 \
  -repo /absolute/path/to/authorized/repository
```

Supported report importers are `nuclei`, `openvas`, and `nessus`.

## Notifications

`notify-webhook`, `notify-slack`, and `notify-email` are explicit delivery
commands. Automatic webhook delivery occurs only when the scan-completed
subscription is enabled.

## Storage and secrets

- `backup-encrypted <path> -key-env <name>`
- `restore-encrypted <path> -confirm -key-env <name>`
- `postgres-migrate`
- `secret-check <name>`
- `secret-set <name> -value-env <name>`
- `secret-rotate <name> -value-env <name>`

## Distributed operation

- `distributed-status`
- `distributed-enqueue <scan-id>`
- `distributed-enroll -agent <id> -public-key <base64>`
- `distributed-heartbeat -agent <id>`
- `distributed-lease -agent <id>`
- `distributed-complete -agent <id> -job <id> -status completed|failed`
- `distributed-agent -agent <id> -coordinator <https-url>`

## Plugins

Plugin subcommands include `plugin-search`, `plugin-install`, `plugin-update`,
`plugin-rate`, and `plugin-registry`. Run the binary without a command for the
complete built-in usage output.

## Common Operator Workflow Examples

```bash
# 1. Guided first-run engagement setup:
enumscan engagement-wizard -target 192.168.1.0/24 -template network -authorization AUTH-2026-001 -output configs/corp.yaml -yes

# 2. Offline validation and effective-plan dry-run:
enumscan -config configs/corp.yaml validate-config

# 3. Execute scan and view findings:
enumscan -config configs/corp.yaml run scan-corp-01
enumscan -config configs/corp.yaml report scan-corp-01 -format executive
enumscan -config configs/corp.yaml report scan-corp-01 -format sarif

# 4. Interactive Terminal Console:
enumscan -config configs/corp.yaml tui

# 5. Backup database with key encryption:
enumscan -config configs/corp.yaml backup-encrypted backups/corp-01.enc -key-env BACKUP_KEY
```
