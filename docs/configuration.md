# Configuration reference

Enumscan uses a deliberately constrained YAML loader. Unknown fields are
rejected; configuration is not arbitrary YAML and does not support anchors or
runtime code. Start from a file in `configs/`.

## Sections

| Section | Purpose |
| --- | --- |
| `database` | SQLite/PostgreSQL selection, pools, and encryption key references |
| `secrets` | Vault, AWS, Azure, GCP, or Kubernetes secret backend |
| `neo4j` | Optional evidence graph synchronization |
| `scope` | Allowed targets and written authorization reference |
| `active_testing` | Separate expiring authorization for intrusive techniques |
| `scheduler` | Worker count, rate limits, and module timeout |
| `discovery` | DNS, liveness, UDP, capture imports, and host limits |
| `portscan` | TCP/UDP ports, profile, raw techniques, and pressure limits |
| `http` | Crawling, APIs, screenshots, cookies, HTTP/3, and gRPC reflection |
| `specialized` | SMB, LDAP, SNMP, cloud, container, database, and protocol checks |
| `passive_intel` | Third-party sources, provider controls, pacing, and quota checks |
| `scan` | Profile, explicit targets, and optional port overrides |
| `reporting` | Output directory and optional loopback LLM advisory |
| `notifications` | Explicit scan-completed webhook subscription |
| `monitoring` | Bounded recurring runs |
| `api` | Dashboard/API token requirement and token environment variable |

## Scope

```yaml
scope:
  allowed_targets: ["192.0.2.0/24", "example.test"]
  authorization: "CHANGE-1234"
```

Addresses, CIDRs, exact domains, and wildcard domains are supported. A domain
scope includes its subdomains. Redirects and emitted events are checked again
so discovery cannot silently expand the engagement.

## Profiles

Built-in profiles are `quick`, `standard`, `exhaustive`,
`external_infrastructure`, `internal_network`, `web_application`,
`api_assessment`, `active_directory`, `kubernetes`, `cloud_infrastructure`,
`bug_bounty`, and `compliance`.

```yaml
scan:
  profile: "web_application"
  targets: ["app.example.test"]
```

Explicit YAML values override profile defaults. A custom profile can be loaded
with `scan.custom_profile`; see `configs/profiles/http-focused.example.yaml`.

## Scheduler bounds

```yaml
scheduler:
  concurrency: 4
  enable_adaptive_workers: false
  min_concurrency: 1
  global_rate_limit_ms: 100
  per_target_rate_limit_ms: 250
  module_timeout_ms: 15000
```

Adaptive workers never exceed `concurrency`. Per-target and global pacing still
apply. Increase limits only when the engagement and target capacity allow it.

## Credentials

YAML stores environment-variable or secret-manager references, never secret
values. Examples include `database.postgres_dsn_env`, `http.auth_cookie_env`,
`neo4j.password_env`, and `api.tokens_env`.

## Templates

List the assessment-specific templates and create a private working copy:

```sh
make scan-templates
make new-scan-config TEMPLATE=web OUTPUT_CONFIG=configs/acme-web.yaml
```

The copier refuses to overwrite an existing file and sets the new file to mode
`0600`. Available template names are:

| Name | Intended starting point |
| --- | --- |
| `external` | Public perimeter, DNS, TLS, HTTP, and services |
| `internal` | Internal host and read-only service inventory |
| `web` | Bounded unauthenticated web application review |
| `api` | REST, GraphQL, OpenAPI, SOAP, and optional gRPC discovery |
| `active-directory` | Unauthenticated AD endpoint fingerprinting |
| `kubernetes` | Kubernetes API and node metadata enumeration |
| `cloud` | Cloud-facing endpoint inventory |
| `bug-bounty` | Conservative program-scoped surface discovery |
| `compliance` | Evidence-oriented service and web hardening review |
| `passive` | Provider-assisted discovery, initially disabled |
| `active-testing` | Separate Tier 4 authorization workflow |

Additional infrastructure templates remain available directly:
`configs/scan.template.yaml`, `configs/production.yaml`,
`configs/postgres.template.yaml`, `configs/secrets.template.yaml`, and
`configs/monitor.template.yaml`.

For the exhaustive field list and defaults, see
[configuration_reference.html](configuration_reference.html) and the annotated
templates.
