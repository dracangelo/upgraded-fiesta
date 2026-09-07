# CLI reference

General form:

```text
enumscan -config <configuration.yaml> <command> [arguments]
```

## Scan and inspect

| Command | Purpose |
| --- | --- |
| `init-db` | Initialize or migrate the configured datastore |
| `run <scan-id>` | Run one scope-validated scan |
| `monitor [-prefix name]` | Run the configured bounded monitoring schedule |
| `server` / `dashboard` | Start the local API and web dashboard |
| `tui` | Open the read-only terminal interface |
| `doctor [-remote] [-format text\|json]` | Validate provider configuration; `-remote` performs explicit bounded provider calls |

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

