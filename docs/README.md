# Enumscan documentation

This directory is the documentation home for operators, administrators, and
contributors. Start with the path matching what you need:

The Markdown files are canonical. Matching HTML pages are generated with
`make docs`; open [index.html](index.html) for the styled offline manual.

## Use enumscan

- [Getting started](getting-started.md) — prerequisites, build, first scan, and first report.
- [Configuration reference](configuration.md) — configuration sections, profiles, scope, and validation.
- [CLI reference](cli.md) — commands and common invocations.
- [Scanning and modules](scanning.md) — discovery, port, HTTP, specialized, passive, and active modules.
- [Reports, dashboard, and API](reporting-api.md) — outputs, local UI, authentication, and integrations.

## Operate enumscan

- [Operations guide](operations.md) — storage, encryption, secrets, monitoring, distributed agents, backup, and release artifacts.
- [Security model](security.md) — trust boundaries, safe defaults, credential handling, and threat model.
- [Tier 4 active testing](tier4_active_testing.md) — the separate authorization gate and current implementation status.

## Extend enumscan

- [Architecture](architecture.md) — event flow, packages, persistence, and extension points.
- [Plugins and marketplace](plugins.md) — manifests, permissions, signing, installation, Lua, and gRPC.
- [Development guide](development.md) — tests, formatting, verification, and contribution workflow.

## Stable legacy links

Older documentation URLs remain available and are regenerated from the
maintained guides so bookmarks and external links continue to work:

- [API reference](api_reference.html)
- [Operator guide](operator_guide.html)
- [Configuration reference](configuration_reference.html)
- [System architecture](architecture.html)
- [Authorized-use guidance](authorized_use.html)
- [Threat model](threat_model.html)
- [Performance tuning](performance_tuning.html)
- [Module developer guide](module_developer_guide.html)
- [Plugin SDK](plugin_sdk.html)
