# Changelog

This file summarizes completed product capabilities. Detailed implementation
history remains available in version control. Until tagged release notes are
backfilled, completed work is grouped under `Unreleased`.

## Unreleased

### Added

- Event-driven scanning with scope enforcement, bounded scheduling, resumable
  state, module checkpoints, structured logging, and deduplication.
- Native SQLite persistence, authenticated field encryption, encrypted
  backup/restore, retention, migration, and evidence custody.
- Host/DNS discovery, TCP/UDP and raw enumeration, service/CPE fingerprinting,
  HTTP crawling, directory/API discovery, screenshots, HTTP/3, and gRPC reflection.
- Specialized protocol enumeration and a normalized passive-intelligence
  provider framework with production credential diagnostics.
- Historical inventory, differential scans, graphs, vulnerability-intelligence
  imports, deterministic risk, correlation, and prioritization.
- Multi-format reporting, explicit notifications, dashboard, REST, GraphQL,
  event streams, TUI, API roles, and durable mutation auditing.
- Authenticated distributed agents with digest/authorization binding, Ed25519
  proof, replay protection, leases, and centralized evidence.
- OS and cloud secret managers, a signed plugin marketplace, Lua/gRPC runtimes,
  cross-platform release security, scan templates, and generated documentation.
- Code-owned capability manifest exposed through CLI, API, and documentation.

### Safety

- Added a separate expiring, operator-identified, environment-acknowledged,
  per-technique authorization gate and impact limits for future Tier 4 probes.
- Kept external providers, credentials, screenshots, notifications, raw
  sockets, distributed listeners, plugins, and intrusive probes opt-in.

