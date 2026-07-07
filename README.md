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
- Raw SYN/UDP scans, advanced TLS tests, AD/SMB enumeration, and vulnerability correlation are planned in `todo.md`.

