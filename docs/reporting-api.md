# Reports, dashboard, and API

## Report formats

Reports are generated from persisted evidence:

- `json` and `csv` for automation.
- `markdown`, `html`, and `pdf` for general delivery.
- `executive` and `technical` for deterministic audience-specific summaries.
- `triage` for evidence-backed rationale and safe follow-up.
- `sarif` for security tooling.
- `neo4j` for graph exchange.

Report generation does not alter findings. Sensitive values pass through the
report redaction layer.

## Dashboard and TUI

The dashboard exposes scan status, metrics, assets, findings, events, logs,
screenshots, saved searches, drift, timelines, and graph views. The TUI is a
read-only local scan browser.

```sh
make dashboard CONFIG=configs/my-scan.yaml
make tui CONFIG=configs/my-scan.yaml
```

## Authentication and roles

Set `api.require_auth: true` and `api.tokens_env` to an environment variable
containing comma-separated `token:role` mappings. Roles are `viewer`, `analyst`,
and `admin`. Token reload is an authenticated administrative mutation. Audit
records store only truncated token fingerprints, roles, actions, statuses, and
scan IDs.

## API groups

- Health and readiness: `/api/v1/health`, `/api/v1/integrations`.
- Scans: `/api/v1/scans`, `/run`, `/pause`, and `/resume`.
- Evidence: `/api/v1/assets`, `/findings`, `/events`, `/search`.
- Streaming: `/api/v1/logs/stream`, `/findings/stream`, `/events/ws`.
- Analysis: `/api/v1/graph`, `/knowledge-graph`, `/timeline`, `/drift`.
- Distributed agents: `/api/v1/distributed/...`.
- Administration: `/api/v1/auth/reload`, `/api/v1/audit`.
- GraphQL: `/query`.

See [api_reference.html](api_reference.html) for methods, parameters, and
response examples.

