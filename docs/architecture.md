# Architecture

Enumscan is a modular event pipeline with durable evidence storage.

```text
configuration -> scope validation -> scheduler -> modules -> events
                                      |             |
                                      +---- datastore ----> reports/API/TUI
```

## Runtime flow

1. The constrained loader applies defaults and a named scan profile.
2. Validation checks authorization, limits, endpoints, credential references,
   and opt-in constraints.
3. The engine creates a scan record and registers profile-selected modules.
4. Initial target events enter the bounded scheduler.
5. Modules consume events, persist evidence, and emit downstream events.
6. Exact/Bloom-assisted deduplication prevents repeated pipeline work.
7. The scan completes only when queued work finishes without failed module runs.
8. Reports and interfaces read persisted evidence rather than mutable module state.

## Packages

| Package | Responsibility |
| --- | --- |
| `cmd/enumscan` | CLI wiring and explicit operator actions |
| `internal/config` | Defaults, profiles, parsing, and validation |
| `internal/scope` | Target authorization checks |
| `internal/engine` | Module registration and scan lifecycle |
| `internal/scheduler` | Queueing, pacing, timeouts, deduplication, adaptive workers |
| `internal/modules` | Discovery and enumeration implementations |
| `internal/store` | SQLite/PostgreSQL persistence, migrations, encryption, secrets |
| `internal/inventory` | History, drift, relationships, and knowledge graph |
| `internal/vulnerability` | Imports, matching, prioritization, risk, and correlation |
| `internal/reporting` | Reports, notifications, redaction, and Neo4j export |
| `internal/api` | Dashboard, REST, GraphQL, streams, auth, and audit |
| `internal/plugin` | Manifests, permissions, marketplace, signatures, Lua, and gRPC |

## Evidence model

The principal records are scans, assets, findings, events, module runs, port
observations, distributed jobs/agents, and audit entries. Evidence includes a
verification or confidence state so heuristic observations remain distinct
from directly observed results.

## Extension points

Native modules implement a name, subscriptions, and event handler. Plugins use
a permissioned manifest and an explicitly selected runtime. New code must keep
scope enforcement, bounded reads/writes, redaction, deterministic reporting,
and test fixtures at the extension boundary.

