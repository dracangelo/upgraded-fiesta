# enumscan

`enumscan` is a CLI-first reconnaissance framework for authorized security assessments. It is structured as an event-driven pipeline: modules discover assets, publish events, persist scan state, and feed later modules such as HTTP enumeration and reporting.

## Documentation

The complete manual is organized in [`docs/README.md`](docs/README.md):
The styled offline HTML edition starts at [`docs/index.html`](docs/index.html)
and can be regenerated with `make docs`.

- [Getting started](docs/getting-started.md)
- [Configuration](docs/configuration.md) and [CLI reference](docs/cli.md)
- [Scanning and modules](docs/scanning.md)
- [Reports, dashboard, and API](docs/reporting-api.md)
- [Operations](docs/operations.md) and [security model](docs/security.md)
- [Architecture](docs/architecture.md), [plugins](docs/plugins.md), and
  [development](docs/development.md)

Current product truth is separated into [`CHANGELOG.md`](CHANGELOG.md),
[`ROADMAP.md`](ROADMAP.md), [`LIMITATIONS.md`](LIMITATIONS.md), and the
code-owned capability manifest (`enumscan capabilities`).

This first scaffold focuses on the core engine, scheduler, networking, crawling-ready HTTP enumeration, SQLite storage, YAML configuration/templates, reporting, and Python scripting hooks.

## Safety Model

Only scan systems you are explicitly authorized to assess. `enumscan` requires targets to match the configured scope before modules run.

Intrusive Tier 4 checks use a second gate and remain disabled by default. An
engagement configuration must set `active_testing.enabled`, provide a future
RFC3339 authorization expiry and operator identity, name each allowed technique,
and reference an environment variable whose value is exactly
`I_ACKNOWLEDGE_ACTIVE_TESTING_IS_AUTHORIZED`. The gate also requires bounded
requests per host, concurrency, and request delay. Enabling the gate never
broadens `scope.allowed_targets`; each implemented probe must additionally be
present in `active_testing.allowed_techniques`. See `configs/scan.template.yaml`.
The complete operator workflow, technique catalog, current runner status, and
fail-closed behavior are documented in
[`docs/tier4_active_testing.md`](docs/tier4_active_testing.md). Start from the
dedicated template with `make active-scan-template`, then run an approved
configuration with `make active-scan CONFIG=<path> SCAN_ID=<id>`.

## Quick Start

```bash
go run ./cmd/enumscan -config configs/example.yaml init-db
go run ./cmd/enumscan -config configs/example.yaml run example-scan
go run ./cmd/enumscan -config configs/example.yaml report example-scan -format markdown
```

Reports are written to `reports/`. Scan state is stored in SQLite at the path configured in YAML.

## PostgreSQL

PostgreSQL is selectable for normal scans. Copy and edit
`configs/postgres.template.yaml`, set its authorization/target placeholders,
export the DSN named by `database.postgres_dsn_env`, then run
`make postgres-migrate CONFIG=configs/postgres.template.yaml` before the first
scan. The pgx datastore uses bounded pool settings and a serialized migration
ledger; `run`, `server`, and `monitor` persist their evidence in PostgreSQL.

## Bounded continuous monitoring

Continuous monitoring is deliberately an explicit, finite operator action. Set
`monitoring.enabled: true`, choose an interval of at least five minutes and a
maximum run count, then run `make monitor CONFIG=configs/monitor.template.yaml`.
Each run uses the same scope-locked configuration and written authorization,
has its own scan ID, and appears in the dashboard history. The command never
creates an unbounded background scanner or adds targets between runs.

## Secret handling

Enumscan supports explicit production adapters for the native OS credential
store (macOS Keychain, Windows Credential Manager, and Linux Secret Service),
HashiCorp Vault KV v2, Kubernetes Secrets, AWS Secrets Manager, Azure Key Vault,
and GCP Secret Manager. Remote endpoints require HTTPS except for loopback
tests, redirects are refused, responses are bounded, and selecting an
unconfigured provider fails closed. Vault/Kubernetes/Azure/GCP credentials can
come from either an environment variable or a projected single-line token file;
the file is reread for every request so workload-token rotation is honored. AWS
uses SigV4 credentials from `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and an
optional `AWS_SESSION_TOKEN`.

Configure a backend under `secrets:`; see `configs/secrets.template.yaml`.
Provider-specific settings are: Vault `endpoint`, `mount`, and token source;
Kubernetes `endpoint`, `namespace`, and token source; AWS `region` (with an
optional endpoint override); Azure `endpoint` and token source; GCP `project`
and token source; OS keychain `service`. `secret-check` confirms availability
without displaying a value. `secret-set` and `secret-rotate` read the new value
only from the environment variable named by `-value-env`. The environment-only
backend remains deliberately read-only.

`database.encryption_key_secret` may name a base64 AES-256 key in the configured
manager, allowing live datastore encryption without placing the key directly
in an Enumscan-specific environment variable.

## Live datastore and backup encryption

Set `database.encryption_key_env` to an environment-variable name containing a
base64-encoded 32-byte AES-256 key. Enumscan then encrypts sensitive scan
evidence before SQLite receives it. AES-256-GCM authenticates every field and
column-specific associated data prevents ciphertext from being moved between
fields. Existing plaintext evidence is migrated atomically when encryption is
first enabled. A key verifier causes startup to fail closed when the key is
missing or incorrect. Equality within one column remains visible to preserve
deduplication and checkpoint lookup; use encrypted storage volumes as an
additional control when this leakage is unacceptable.

For protected backup artifacts, place a separate base64-encoded 32-byte
AES-256 key in `ENUMSCAN_BACKUP_KEY` and run
`make backup-encrypted CONFIG=configs/my-scan.yaml BACKUP_PATH=/secure/path/enumscan.esb`.
Backups are chunked AES-256-GCM ciphertext with authentication, use `0600`
file permissions, and do not retain the key. Restore is intentionally a
separate destructive command: `enumscan ... restore-encrypted <path> -confirm`.
Protect, rotate, and back up the key through your approved secret-management
system; losing it makes that encrypted backup unrecoverable.

## Dashboard API tokens

The local dashboard remains unauthenticated by default because it binds only to
`127.0.0.1`. To require API authentication, set `api.require_auth: true` and
`api.tokens_env: "ENUMSCAN_API_TOKENS"`, then export comma-separated
`token:role` entries such as `viewer-token:viewer,operator-token:analyst`.
Roles are server-assigned: `viewer` is read-only, `analyst` cannot delete, and
`admin` can perform allowed mutations. Tokens never appear in YAML, and the
legacy `X-User-Role` request header has no authority.

To rotate a configured token mapping without restarting the local server,
update the environment variable and have a currently valid `admin` send
`POST /api/v1/auth/reload`. The endpoint applies the replacement mapping only
when it parses successfully, returns only its count, and is included in the
durable mutation audit trail. A new token should overlap with the old admin
token until the reload has succeeded.

Every state-changing API request is recorded in the local append-only audit
table with a truncated SHA-256 token fingerprint, assigned role, action,
response status, and scan ID when supplied. Token values and request bodies are
never retained by this audit trail.

Operators can retrieve recent records from `GET /api/v1/audit?limit=50`.
When API tokens are enabled, this endpoint is restricted to the server-assigned
`admin` role; it remains available to the local operator when authentication is
disabled.

## Distributed scanning

The local datastore now supports durable coordinator-owned scan-job records and
atomic time-bounded leases. Each job carries an authorization reference and a
SHA-256 configuration digest; only the leasing agent can mark it completed or
failed. Coordinator state also supports validated agent enrollment records and
heartbeat tracking. Enrolled Ed25519 public keys authenticate every remote
heartbeat, lease, evidence upload, and completion request; signed timestamps
and durable one-use nonces prevent replay. Status responses expose only key
fingerprints. Agents retain an operator-provisioned copy of the authorized
configuration and reject a lease unless both its SHA-256 digest and written
authorization reference match.

Use `make distributed-status CONFIG=configs/my-scan.yaml` to inspect the local
coordinator ledger. Local operators can enqueue a digest-bound plan, enroll a
fingerprint-only agent record, record a heartbeat, lease a queued record, and
record lease-owner completion with the `distributed-*` CLI commands. Start a
TLS coordinator with `enumscan ... server -listen 0.0.0.0 -tls-cert cert.pem
-tls-key key.pem`. An enrolled node runs one available job with `enumscan ...
distributed-agent -agent AGENT_ID -coordinator https://coordinator:8080`; its
unpadded base64 Ed25519 private key is read from
`ENUMSCAN_AGENT_PRIVATE_KEY`. The agent executes only its local scope-validated
configuration and returns bounded assets, findings, and events to centralized
coordinator storage before completing the lease. Plain HTTP is accepted only
for loopback development.

Use `-format executive` or `-format technical` to generate local, deterministic
Markdown summaries from persisted evidence. These reports preserve each finding's
verification state and do not claim compromise, exploitation, or AI analysis.
Use `-format triage` for evidence-backed risk rationale and safe follow-up
recommendations limited to scoped verification, inventory, and remediation.

For an optional local Ollama advisory, configure `reporting.local_llm_url` as a
loopback `http://127.0.0.1:11434/api/generate` (or `localhost`) endpoint and
set `reporting.local_llm_model`. Then run `make local-llm-summary`. Enumscan
sends only local deterministic summaries to that endpoint, labels the result as
unverified advisory text, and never turns it into a finding or scan decision.

For explicit Neo4j synchronization, configure `neo4j.uri`, `neo4j.username`,
and `neo4j.password_env` (for example `ENUMSCAN_NEO4J_PASSWORD`), then run
`make sync-neo4j CONFIG=configs/my-scan.yaml SCAN_ID=<id>`. Remote endpoints
must use HTTPS; HTTP is accepted only for a loopback Neo4j test/deployment.

To subscribe an approved webhook to healthy `scan.completed` events, set
`notifications.enable_scan_completed_webhook: true` and an approved
`notifications.webhook_url`. Delivery uses the same bounded, redirect-refusing
webhook transport, stays disabled by default, and does not change the scan's
completed result if the notification system is unavailable.

For a guided, repeatable engagement, run `make engagement-wizard`. It prompts
for a single IP/CIDR/hostname and written authorization reference, writes a
new mode-`0600` scope-locked configuration, and never overwrites an existing
file. Validate the result before scanning:

```sh
make engagement-wizard
make validate-config CONFIG=configs/engagement.yaml
make scan CONFIG=configs/engagement.yaml SCAN_ID=engagement-001
```

The dashboard offers the same workflow through **New engagement**. It
downloads a reviewable YAML file rather than changing the running server's
scope. Where dashboard authentication is enabled, an admin role is required.

For an easy one-off, authorized scan, run `make interactive-scan`. It prompts
for an IP/CIDR, scan type (`quick`, `standard`, or `exhaustive`), and the
written authorization reference, then creates a temporary scope-locked config.
For a repeatable engagement, use `make scan-template`, edit the generated
`configs/my-scan.yaml`, and run `make scan CONFIG=configs/my-scan.yaml SCAN_ID=<id>`.
Run `make scan-templates` to list focused starting points, then create one with
`make new-scan-config TEMPLATE=web OUTPUT_CONFIG=configs/acme-web.yaml`.

`scan.profile` selects one of `quick`, `standard`, `exhaustive`,
`external_infrastructure`, `internal_network`, `web_application`,
`api_assessment`, `active_directory`, `kubernetes`, `cloud_infrastructure`,
`bug_bounty`, or `compliance`. It applies a safe module plan, TCP port set,
and scheduler defaults; values explicitly set in the YAML remain overrides.
For a focused reusable plan, set `scan.custom_profile` to a profile file such
as `configs/profiles/http-focused.example.yaml`.

## Local Git-history secret review

For a repository you are authorized to review, run
`make git-secrets CONFIG=configs/my-scan.yaml SCAN_ID=repo-review REPO=/absolute/path/to/repository`.
The repository path is always explicit. The command is read-only and local:
it never contacts a remote, bounds history inspection, and records only a
redacted fingerprint plus commit ID—never a usable credential value.

Run `make tui CONFIG=configs/my-scan.yaml` for a read-only terminal view of
the most recent scans. Use arrow keys (or `j`/`k`) to select a scan, `r` to
refresh, and `q` to quit.

## Container and release artifacts

`make build-cross` produces Linux AMD64, macOS ARM64, and Windows AMD64
binaries in `dist/`. Release CI additionally runs
`make reproducible build-cross release-archives system-packages
verify-system-packages VERSION=<tag> checksums` to produce versioned
Linux/macOS `.tar.gz`, Windows `.zip`, Debian, RPM, Homebrew-formula, and Scoop
manifest artifacts. The checksum manifest contains relative names so it can be
used directly after a release download; the workflow keyless-signs every
artifact and creates GitHub build-provenance attestations.
`make image` builds the non-root local container image;
mount an engagement-specific configuration and writable database directory at
`/data`. CI runs the complete tests and executes a native binary on hosted
Linux, macOS, and Windows runners. CodeQL, dependency review, Govulncheck,
CycloneDX generation, and a high-severity-failing container scan run before a
release can publish.

Tagged releases publish binaries and multi-architecture Linux images only from
the `production-release` GitHub Environment. Configure required reviewers,
prevent self-review/bypass, restrict it to release tags, and set its
`APPROVED_CONTAINER_PUBLISH` variable to `true`; otherwise publication fails
closed. Published images include BuildKit provenance/SBOM data, a keyless
signature over the immutable digest, and a registry-hosted GitHub provenance
attestation. Consumers should verify binaries with `gh attestation verify` and
images using their `oci://ghcr.io/...` reference.

The scheduled threat-intelligence workflow builds an incremental Enumscan feed
from NVD modifications, the CISA Known Exploited Vulnerabilities catalog, and
FIRST EPSS. It records source and output checksums, tests the transformer,
attests the feed plus provenance metadata, and retains the bundle for reviewed
import. Scheduled operation is fail-closed until the repository variable
`PRODUCTION_THREAT_INTELLIGENCE` is `true`; manual dispatch remains available.
Configure the `production-threat-intelligence` Environment and optionally its
`NVD_API_KEY` secret for production rate limits. After verifying the attestation
and checksums, import the delta with `import-nvd`, passing the generated time as
the version and the provenance artifact as the operational record.

## Trusted plugin marketplace and runtimes

Normal scans never load or execute files merely because they appear in
`plugins/` or the installation directory. Marketplace discovery also has no
default service: every search, rating, installation, and update requires an
explicit `-registry` URL. HTTPS is mandatory except for loopback development.

Run `plugin-search -registry https://registry.example -query headers` to search.
Use `plugin-install` or `plugin-update` with `-id`, `-dir`, and
`-trusted-key-env`; the named environment variable must contain the operator's
pinned Ed25519 public key in hex or base64. Downloads refuse redirects, are
size-bounded, and must match both the registry checksum and signature before an
atomic, versioned installation. Installed files are verified again against the
signed package before explicit activation. Ratings are submitted with
`plugin-rate`. Community plugins are clearly labelled and follow the same
signature policy; `plugins/community` contains a constrained example.

The marketplace server is available through `plugin-registry`. It requires an
explicit public base URL, a JSON publication catalog, and an Ed25519 private key
from the environment. Non-loopback listeners require `-tls-cert` and
`-tls-key`. The server provides discovery/search, version metadata, ratings,
and signed package downloads.

Lua plugins run in an embedded interpreter with context cancellation, output
limits, and only base, table, string, and math libraries. File, process, and OS
libraries are absent. Network access requires the manifest permission and is
restricted to the event target. gRPC plugins use the protobuf Struct contract
at `/enumscan.plugin.v1.Plugin/Execute`; remote endpoints require TLS and
plaintext is accepted only on loopback. Both runtimes enforce declared write
permissions. This application-level isolation does not claim to be a general
OS container sandbox; deploy remote gRPC plugins under the operator's normal
process/container controls.

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
plugins              Inactive SDK groundwork; not loaded by production scans
```

## Notes

- SQLite uses a native Go driver with WAL mode, a busy timeout, and serialized pooled writes for reliable concurrent scan persistence.
- Set `scheduler.enable_adaptive_workers: true` to opt into bounded live worker scaling between `scheduler.min_concurrency` and `scheduler.concurrency`. It uses observed module durations, persists the current worker capacity, and never exceeds the configured rate limits or concurrency ceiling. The shipped configurations keep it disabled for predictable fixed-concurrency operation.
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

The HTTP module records response metadata, security-header findings, TLS certificates, SANs, supported TLS versions, negotiated ciphers, robots.txt and sitemap URLs, scoped crawl links, JavaScript endpoints, potential client-side secret hints, and API discovery hits. Screenshot capture is disabled unless `http.enable_screenshots` is paired with an absolute, operator-approved local browser wrapper, an absolute artifact directory, and arguments containing `{url}` and `{output}`. The wrapper is responsible for the engagement's browser-network policy. Enumscan records a gallery item only after it verifies a PNG artifact, its size, and its SHA-256 checksum.

## Directory and API Enumeration

The optional `directory_api_enumerator` performs a bounded, scope-checked pass over common and technology-specific paths. It derives additional paths from first-party JavaScript, checks for exposed backups, Git/SVN metadata and environment files, and records OpenAPI, GraphQL, SOAP/WSDL and gRPC reflection evidence. Configure `http.max_directory_paths` and `http.directory_wordlist` to keep the request volume appropriate for the authorization you hold.

Set `http.enable_cookie_jar: true` only when the engagement permits preserving
server-issued cookies across a scan. It does not submit credentials, attempt a
login, or persist cookies after the process exits.

For authenticated enumeration without a login workflow, set
`http.enable_authenticated_crawling: true` and `http.auth_cookie_env` to an
environment-variable name such as `ENUMSCAN_AUTH_COOKIE`. Enumscan injects
that operator-supplied session cookie only into scope-checked HTTP requests,
keeps it in memory, and never stores or reports the value. The written
authorization must cover the authenticated session and the intended crawling.

It also checks validated Mercurial metadata and common editor/backup temporary files. With `http.enable_source_map_analysis`, it parses scoped source maps without storing source content, records discovered endpoints, and sends only redacted secret fingerprints through the normal heuristic secret workflow. API endpoint responses are inspected for advertised rate-limit headers and JSON/OpenAPI schema shape; no unsafe API methods are sent.

## Container and Kubernetes Enumeration

When `specialized.enable_container` is enabled, the specialized module
identifies exposed Docker API sockets, registries, runtime endpoints, and
Kubernetes service metadata from safe responses. It does not retrieve Compose
files, Kubernetes secrets, or instance credentials.

The same explicit opt-in also identifies scoped Podman API and containerd HTTP health endpoints from real responses. Database enumeration identifies Cassandra, ClickHouse, InfluxDB, MSSQL, MySQL, PostgreSQL, Redis, MongoDB, Elasticsearch, and Memcached protocol evidence without attempting passwords, privilege changes, or data extraction. LDAP RootDSE responses yield observed naming contexts without directory-object enumeration. SNMP checks require operator-supplied communities; no default community strings are guessed. HTTP response headers can also identify AWS Lambda, Azure Functions, and GCP Cloud Run/Functions endpoints.

## Passive Intelligence

Set `passive_intel.enabled: true` and choose sources in `passive_intel.sources` to enable third-party lookups. The global setting is the master switch; `provider_controls` entries such as `shodan=false` or `github=true` can then disable a selected provider or explicitly add one. `provider_versions` pins supported API contracts with entries such as `github=2026-03-10`. API credentials are read from environment variables (`SHODAN_API_KEY`, `CENSYS_API_ID`/`CENSYS_API_SECRET`, `SECURITYTRAILS_API_KEY`, `FOFA_EMAIL`/`FOFA_API_KEY`, `VIRUSTOTAL_API_KEY`, `HUNTER_API_KEY`, `WHOISXML_API_KEY`, `HIBP_API_KEY`, `GITHUB_TOKEN`, `GITLAB_TOKEN`, `DNSDB_API_KEY`, `ABUSEIPDB_API_KEY`, `GREYNOISE_API_KEY`, `BINARYEDGE_API_KEY`, `URLSCAN_API_KEY`, and `OTX_API_KEY`), not YAML. Supported source names include `virustotal`, `shodan`, `censys`, `securitytrails`, `fofa`, `hunter`, `whoisxml`, `hibp`, `github`, `gitlab`, `dnsdb`, `circl_cve`, `abuseipdb`, `greynoise`, `binaryedge`, `urlscan`, `otx`, `wayback`, `bucket`, and `paste`. Shodan, Censys, AbuseIPDB, GreyNoise, and BinaryEdge are IP-only lookups. HIBP queries only an account-verified domain and discards returned email aliases before persistence. Hunter email addresses and GitLab code snippets are likewise discarded. CIRCL CVE Search runs only when service fingerprinting supplies a valid CPE vendor/product; it never treats a hostname as a software product. urlscan.io is queried only through its historical search API—Enumscan never submits a URL for a third party to scan. `paste` requires `PASTE_MONITOR_URL`; GitLab accepts `GITLAB_API_URL` for self-hosted instances. `provider_min_interval_ms` spaces requests to each provider (default 1000 ms); `max_retry_after_ms` bounds compliant waits after a provider returns HTTP 429 (default 30000 ms). Duplicate source/host requests from the same scan are suppressed in memory, while later scans request fresh evidence.

Run `enumscan -config configs/my-scan.yaml doctor` before a scan to inspect the local source configuration. It never contacts a provider or prints a secret; it verifies required variables and rejects malformed credential shapes locally without claiming that a credential is valid. Use `-format json` for automation. `doctor -remote` (or `make doctor-remote`) is a separate, explicit action: it uses bounded provider-specific account or identity endpoints where available, may consume API quota, and reports reachability, credential acceptance or rejection, and rate limiting. Set `enable_quota_discovery` to retain structured provider-supplied limit, remaining, used, reset, and resource data when available. Set `enable_update_checks` to evaluate pinned/selected versions and provider `Deprecation` or `Sunset` signals; this is a contract-signal check, not a package registry updater. Remote diagnostics never print key values or claim account entitlement. Sources such as `wayback` and `bucket` make third-party/direct HTTPS requests when enabled for a scan, so enable them only when those requests are within the engagement authorization.

The local dashboard's **Integrations** view exposes the same offline readiness
report at `GET /api/v1/integrations`, including declared capabilities and any
missing environment-variable names. It never reveals values or calls a provider.

To notify an approved system, explicitly run `make notify-webhook` with a scan
ID and HTTPS endpoint. Enumscan posts one bounded evidence-only summary, does
not follow redirects, and never sends a webhook automatically during a scan.
For a Slack incoming webhook, use `make notify-slack` with
`SLACK_WEBHOOK_URL`; it sends a compact summary under the same safeguards.
For explicit email, use `make notify-email` with an SMTP server, sender, and
recipient. SMTP requires STARTTLS outside localhost; set `SMTP_USERNAME` and
`ENUMSCAN_SMTP_PASSWORD` together when authentication is required.

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

Start the local API with `go run ./cmd/enumscan -config configs/example.yaml server` and open `http://127.0.0.1:8080/`. The dashboard provides scan health/progress, asset and relationship explorers, an event timeline, server-side asset/finding search, saved queries, a verified screenshot gallery, and a dark/light theme. It refreshes scan state every five seconds. The gallery serves only checksum-verified screenshot artifacts from the configured output directory.
