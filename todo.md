# Recon OS TODO

> Goal: Build a modular, event-driven reconnaissance and enumeration platform for authorized security assessments.
>
> Release-audit rule: an item is checked only when it has an executable,
> production-scoped implementation and meaningful coverage. See
> `ENTERPRISE_RELEASE_AUDIT.md` for current ship blockers and `FEATURE_ADHERENCE.md`
> for the safe-enumeration feature boundary.
>
> This file is the detailed historical work ledger. Use `OPEN_WORK.md` as the
> single checkable list of remaining work, `CHANGELOG.md` for completed history,
> `LIMITATIONS.md` for current boundaries, and `enumscan capabilities` for
> authoritative runtime status.

---

# 1. Foundation

- [x] Create CLI-first Go project structure.
- [x] Add SQLite-backed scan state and asset storage.
- [x] Add PostgreSQL backend (selectable runtime datastore; PostgreSQL-native recovery validation remains open in `OPEN_WORK.md`).
- [x] Add explicit optional Neo4j HTTP transaction synchronization for
  persisted scan assets and findings; credentials are environment-supplied.
- [x] Add constrained YAML configuration.
- [x] Add scan templates.
- [x] Add scope enforcement.
- [x] Add scope inheritance.
- [x] Add scan scheduling.
- [x] Add recurring scan profiles.
- [x] Add event-driven scheduler.
- [x] Define stable module interface.
- [x] Add JSON reports.
- [x] Add Markdown reports.
- [x] Add HTML reports.
- [x] Add PDF reports.
- [x] Add SARIF export.
- [x] Add CSV report export.
- [x] Add REST API.
- [x] Add WebSocket event stream.
- [x] Add GraphQL API.

---

# 2. Core Engine

- [x] Replace SQLite CLI bridge with native Go SQLite driver.
- [x] Add resumable scans.
- [x] Add module checkpoints.
- [x] Add structured logging.
- [x] Add cancellation support.
- [x] Add module timeout policies.
- [x] Add global rate limits.
- [x] Add per-target rate limits.
- [x] Add adaptive worker pools to the scan scheduler.
- [x] Add authenticated distributed scanning with durable leases and centralized evidence ingestion.
- [x] Add digest-bound, Ed25519-authenticated remote scan agents.
- [x] Add task priority queues to the scan scheduler.
- [x] Add scan deduplication.
- [x] Add plugin dependency resolution.
- [x] Add scan cache.

---

# 3. Asset Inventory

- [x] Build persistent asset inventory.
- [x] Store historical assets.
- [x] Store historical services.
- [x] Store technologies.
- [x] Store certificates.
- [x] Store vulnerabilities.
- [x] Store secrets.
- [x] Store browser-captured screenshots.
- [x] Track first seen.
- [x] Track last seen.
- [x] Track asset ownership.
- [x] Track scan history.
- [x] Build asset relationship graph.

---

# 4. Discovery

- [x] CIDR expansion.
- [x] Reverse DNS.
- [x] Passive DNS import.
- [x] Certificate Transparency import.
- [x] ASN lookup.
- [x] RDAP lookup.
- [x] Wildcard detection.
- [x] CDN detection.
- [x] Cloud provider detection.
- [x] Load balancer detection.
- [x] IPv6 discovery.
- [x] ARP discovery.
- [x] Virtual host discovery.
- [x] Host clustering.
- [x] ICMP ping sweep host discovery.
- [x] TCP SYN & ACK live host probing.
- [x] UDP live host discovery probes (DNS, NTP).
- [x] SNMP live-host probe (requires explicitly supplied community credentials).
- [x] Passive network packet capture & live traffic discovery.
- [x] DNS record enrichment (TXT/SPF, DMARC, SRV) with explicit operator opt-in.
- [x] Scope-checked passive capture-file import.

---

# 5. Port Scanning

- [x] TCP Connect scanning.
- [x] SYN scanning.
- [x] ACK scanning.
- [x] FIN scanning.
- [x] NULL scanning.
- [x] XMAS scanning.
- [ ] Idle scanning. // intentionally excluded: requires an uninvolved third-party host
- [x] Fragmented packet scanning.
- [ ] Decoy scanning. // intentionally excluded: spoofing is not part of authorized enumeration
- [x] UDP scanning.
- [x] Banner grabbing.
- [x] Adaptive timing.
- [x] Scan profiles.
- [x] Differential port scanning.
- [x] Port history tracking.
- [x] TCP Window scanning.
- [x] TCP Maimon scanning.
- [x] Two-phase port scan pipeline (fast raw-socket sweep followed by deep service probe).
- [x] UDP service-specific probes (TFTP, SIP, IKE, RPC, NetBIOS, mDNS, SSDP, RADIUS).
- [x] Bounded concurrent two-phase TCP-connect scanning with open-port-only enrichment.
- [x] Durable per-scan port observation history.

---

# 6. Service Fingerprinting

- [x] SSH
- [x] FTP
- [x] SMTP
- [x] SMB
- [x] LDAP
- [x] Redis
- [x] Databases
- [x] Kubernetes
- [x] Normalize versions.
- [x] Generate CPE candidates.
- [x] Store evidence.
- [x] Confidence scoring.
- [x] Passive fingerprinting.
- [ ] OS fingerprint improvements. // passive packet traits can be retained when supplied, but no collector is integrated
- [ ] TCP/IP stack OS fingerprinting (TTL, TCP window size, option ordering analysis). // requires passive packet evidence or a raw-packet collector
- [x] Application runtime version fingerprinting (OpenSSL, Python, Go, Java, Ruby, Node.js, Gunicorn, Werkzeug, Jetty).

---

# 7. HTTP & Web Enumeration

- [x] TLS certificates.
- [x] SAN extraction.
- [x] TLS versions.
- [x] Cipher suites.
- [x] Security headers.
- [x] Robots.txt.
- [x] Sitemap.
- [x] Recursive crawler.
- [x] Authenticated crawling.
- [x] Cookie support.
- [x] JavaScript parsing.
- [x] Endpoint extraction.
- [x] Secret extraction.
- [x] API discovery.
- [x] Screenshot queue.
- [x] Browser screenshot renderer.
- [x] HTTP/2 fingerprinting.
- [x] HTTP/3 transport support.
- [x] Favicon fingerprinting.
- [x] WebAssembly analysis.
- [x] SPA route discovery.
- [ ] Dynamic rendering.
- [ ] Dedicated SSL/TLS vulnerability verification (Heartbleed, ROBOT, CRIME, BREACH).
- [x] OCSP status checking.
- [x] HPKP (Public Key Pinning) header audit.
- [x] Web Application Manifest (manifest.json) analysis.
- [x] Redirect chain & canonical URL tracking.
- [x] Allowed HTTP Verbs/Methods enumeration (OPTIONS, TRACE, PUT, DELETE).
- [x] Response timing, body-size, compression, and default-error-page profiling.
- [x] Error page & default page fingerprinting.
- [x] Response timing & compression (gzip, brotli, deflate) audit.
- [ ] External gobuster/dirb integration.

---

# 8. Technology Detection

- [x] WordPress enumeration.
- [x] Drupal enumeration.
- [x] Joomla enumeration.
- [x] Laravel enumeration.
- [x] Django enumeration.
- [x] Flask enumeration.
- [x] Spring Boot enumeration.
- [x] ASP.NET enumeration.
- [x] Jenkins enumeration.
- [x] GitLab enumeration.
- [x] Exchange enumeration.
- [x] Kubernetes dashboard detection.
- [x] Elasticsearch detection.
- [x] Redis exposure checks.
- [x] MongoDB exposure checks.
- [x] Frontend framework detection (React, Vue, Angular, Next.js, jQuery, Bootstrap, Tailwind).
- [x] E-commerce & CMS technology fingerprinting (Magento, Ghost, Symfony).

---

# 9. Directory & API Enumeration

- [x] Adaptive wordlists.
- [x] Technology-aware wordlists.
- [x] Wordlist generation from JavaScript.
- [x] Backup file detection.
- [x] Git exposure.
- [x] SVN exposure.
- [x] Environment file discovery.
- [x] GraphQL schema extraction.
- [x] SOAP enumeration.
- [x] gRPC reflection.
- [x] OpenAPI validation.
- [x] Mercurial (.hg) repository exposure detection.
- [x] Source map (.map) parsing and endpoint/secret extraction.
- [x] Temporary files (.swp, ~, .bak, .old, .tmp) detection.
- [x] API rate limit & JSON schema analysis.

---

# 10. Specialized Enumeration

- [x] SMB
- [x] LDAP
- [ ] Authenticated Active Directory enumeration.
- [x] SNMP.
- [x] Kubernetes
- [x] Cloud assets
- [x] Databases
- [x] Docker socket detection.
- [x] Docker registry discovery.
- [x] Container runtime enumeration.
- [ ] Docker Compose discovery. // excluded from safe enumeration because compose files commonly contain credentials
- [ ] Kubernetes secrets discovery.
- [x] Full DNS Record enumeration (SOA, NS, MX, TXT, CAA, SRV, CNAME).
- [ ] DNS Zone Transfer (AXFR) testing & DNSSEC NSEC/NSEC3 zone walking.
- [ ] DNS cache snooping.
- [ ] SMB share permissions & anonymous session auditing.
- [x] LDAP naming-context discovery from an observed anonymous RootDSE response.
- [ ] Kerberoasting target identification (SPN enumeration).
- [ ] LAPS (Local Administrator Password Solution) detection & ACL delegation audit.
- [ ] SSH host key, cipher suite, and authentication method enumeration.
- [ ] FTP writable directory auditing & anonymous login checks.
- [ ] SMTP VRFY/EXPN user enumeration and open relay testing.
- [ ] SNMP MIB walk for system processes, installed software, network routes, ARP tables, and storage devices.
- [ ] Database Engine Enumeration (Cassandra, ClickHouse, InfluxDB, MSSQL, Oracle).
- [ ] Podman & Containerd runtime enumeration.
- [ ] Cloud Instance Metadata Service (IMDSv1 / IMDSv2) reachability auditing.
- [x] Serverless endpoint identification from observed AWS Lambda, Azure Functions, and GCP Cloud Run/Functions response headers.
- [x] Safe protocol identification for Cassandra, ClickHouse, InfluxDB, Podman, and containerd HTTP endpoints.

---

# 11. Passive Intelligence

- [x] Shodan integration with production credential validation.
- [x] Censys integration with production credential validation.
- [x] SecurityTrails integration with production credential validation.
- [x] FOFA integration with production credential validation.
- [x] VirusTotal integration with production credential validation.
- [x] Offline historical URL import from operator-provided, scoped exports.
- [x] GitHub code search with production credential validation.
- [x] GitLab search with production credential validation.
- [x] Hunter.io domain search with production credential validation.
- [x] WhoisXML API subdomain lookup with production credential validation.
- [x] Have I Been Pwned verified-domain lookup with production credential validation.
- [x] DNSDB passive DNS lookup with production credential validation.
- [x] CIRCL CVE Search for service-fingerprint CPEs.
- [x] Public bucket discovery.
- [x] Paste site monitoring.

---

# 12. Authentication Intelligence

- [x] OAuth detection.
- [x] OIDC detection.
- [x] SAML detection.
- [x] JWT detection.
- [x] MFA detection.
- [x] Password policy detection.
- [x] Account lockout detection.
- [x] Session management analysis.
- [x] SSO provider detection.

---

# 13. Secret Intelligence

- [x] AWS key detection.
- [x] Azure credential detection.
- [x] GCP credential detection.
- [x] JWT secret detection.
- [x] API key extraction.
- [x] Private key discovery.
- [x] Secret validation.
- [x] Secret risk scoring.
- [ ] Secret extraction from Git commit history.

---

# 14. Vulnerability Intelligence

- [x] Finding schema.
- [x] NVD importer.
- [x] CPE matching.
- [x] Nuclei report importer.
- [x] OpenVAS report importer.
- [x] Nessus report importer.
- [x] KEV correlation.
- [x] EPSS auto-prioritization.
- [x] Exploit availability tracking.
- [x] Misconfiguration engine.
- [x] Detection rules engine.
- [ ] Active Web Vulnerability Engine (SQLi, XSS, SSRF, LFI/RFI, XXE, SSTI, CORS, Host Header Injection, HTTP Request Smuggling, Prototype Pollution). // passive CORS/parameter heuristics are implemented
- [x] CIS Benchmark & Security Hardening compliance checks.
- [ ] Credentialed scanning engine (SSH / WinRM authenticated patch & package auditing).
- [x] Local offline NVD JSON feed mirror & version backporting analysis.

---

# 15. Correlation Engine

- [x] Evidence-backed exposure-chain correlation from persisted findings and assets.
- [x] Neo4j export.
- [x] Asset graph.
- [x] Trust relationship graph.
- [x] Secret correlation.
- [x] Authentication correlation.
- [x] Lateral movement graph.
- [x] Business impact scoring.
- [x] Attack chain visualization.
- [ ] Multi-step attack path correlation rules (linking web findings to cloud credentials & data exposures).

---

# 16. Risk Engine

- [x] Risk scoring.
- [x] Internet exposure scoring.
- [x] Asset criticality.
- [x] Business context.
- [x] EPSS integration.
- [x] KEV integration.
- [x] Public exploit scoring.
- [x] Composite risk calculation.

---

# 17. Differential Analysis

- [x] Compare scans.
- [x] Detect new hosts.
- [x] Detect removed hosts.
- [x] Detect new ports.
- [x] Detect service changes.
- [x] Detect certificate changes.
- [x] Detect technology changes.
- [x] Detect vulnerability changes.
- [x] Generate change reports.

---

# 18. Automation

- [ ] Event subscriptions. //skip for now
- [x] Automatic module chaining.
- [x] Automatic re-enumeration.
- [x] Scheduled scans.
- [ ] Alerting. //skip for now
- [x] Webhooks.
- [x] Slack notifications.
- [x] Email notifications.

---

# 19. Plugin SDK

- [x] Plugin manifest.
- [x] gRPC plugins.
- [x] Lua plugins.
- [x] Permissions.
- [x] Event subscriptions.
- [x] Sample plugin.
- [x] Plugin marketplace server and trusted registry integration.
- [x] Trusted plugin signing policy and verification.
- [ ] OS-level plugin sandboxing.
- [ ] Safe hot plugin reload.

---

# 20. Operator Experience

- [x] Web dashboard.
- [x] Live scan progress with real worker and queue telemetry.
- [x] Asset explorer.
- [x] Graph explorer.
- [x] Screenshot gallery backed by captured image artifacts.
- [x] Timeline view.
- [x] Search engine.
- [x] Saved queries.
- [x] Dark mode.

---

# 21. AI Assistance

- [x] Executive report summaries.
- [x] Technical report summaries.
- [x] Finding explanation.
- [x] Suggested next enumeration steps.
- [x] Attack path explanation.
- [x] Risk justification.
- [x] Local LLM support.

---

# 22. Testing

- [x] Unit tests.
- [x] Integration tests.
- [x] Performance benchmarks.
- [x] Fuzz testing.
- [x] Regression testing.
- [x] Plugin compatibility tests.

---

# 23. CI/CD

- [x] GitHub Actions.
- [x] Static analysis.
- [x] Security scanning.
- [x] Dependency auditing.
- [x] Cross-platform builds.
- [x] Automatic releases.
- [x] Docker images.

---

# 24. Documentation

- [x] Architecture documentation.
- [x] Module developer guide.
- [x] Plugin SDK documentation.
- [x] REST API documentation.
- [x] Operator guide.
- [x] Configuration reference.
- [x] Authorized-use guidance.
- [x] Threat model.
- [x] Performance tuning guide.

---

# 25. Data Handling & Secrets Protection

- [x] Encryption at rest for the findings datastore.
- [x] Secret redaction in generated reports.
- [x] Secrets manager integration for the tool's own credentialed-scan credentials.
- [x] Access control and audit log — who ran what scan, when.
- [x] Evidence chain-of-custody logging per engagement.

---

# 26. Advanced Intelligence & Modern Web

- [x] Add technology stack fingerprinting with Wappalyzer JSON signature rules.
- [x] Add dynamic tech-aware directory fuzzing with automatic 404/wildcard detection.
- [ ] Add historical URL harvesting from Wayback Machine, Common Crawl, and OTX (`gau`/`waybackurls`).
- [ ] Add VirusTotal API reputation queries and native `go-yara` static artifact scanning.
- [ ] Add Out-of-Band (OOB) interaction listener service for blind SSRF/RCE detection.
- [ ] Add Kerberos pre-authentication user enumeration and AS-REP roasting checks.
- [x] Add BloodHound-compatible JSON/graph export for Active Directory findings.
- [x] Add differential scan engine (comparing DB runs to identify net-new assets and resolved flaws).
- [x] Add terminal dashboard (TUI) powered by `charmbracelet/bubbletea`.

---

# 27. Integrations

## Integration Framework

- [x] Build a production passive-provider catalog shared by runtime requests
  and offline diagnostics. It contains only documented capabilities,
  credential-variable names, target constraints, and opt-in remote-probe
  eligibility—never simulated provider state or quota.
- [x] Define integration interface.
- [x] Add integration lifecycle management.
- [x] Add explicit opt-in remote provider reachability, rejection, and
  rate-limit diagnostics for supported configured passive-intelligence sources.
  The default `doctor` remains offline; remote diagnostics can consume quota and
  show a quota value only when a provider returns a header.
- [x] Add provider-specific credential, quota, and API-contract diagnostics.
- [x] Add bounded, per-provider passive-intelligence request pacing.
- [ ] Add integration caching.
- [x] Add bounded retry/backoff policies with HTTP `Retry-After` handling for
  passive-intelligence providers.
- [x] Add offline provider capability discovery through `enumscan doctor` and
  the read-only dashboard/API integration-status view.

## Bring Your Own API Keys

- [x] VirusTotal
- [x] AbuseIPDB (read-only documented IP check; `ABUSEIPDB_API_KEY`)
- [x] Shodan
- [x] Censys
- [x] SecurityTrails
- [x] GreyNoise (read-only documented IP community lookup; `GREYNOISE_API_KEY`)
- [x] BinaryEdge (read-only documented IP observation lookup; `BINARYEDGE_API_KEY`)
- [x] FOFA
- [x] AlienVault OTX (read-only indicator context; `OTX_API_KEY`)
- [x] URLScan.io (read-only historical search; `URLSCAN_API_KEY`; no URL submission)
- [x] Hunter.io
- [x] WhoisXML API
- [x] Have I Been Pwned
- [x] GitHub
- [x] GitLab
- [x] DNSDB
- [x] CIRCL CVE Search

## Integration Management

- [x] Enable/disable integrations with explicit per-provider overrides.
- [x] Validate provider credential shape locally and acceptance remotely.
- [x] Show local configured-provider status and missing setting names without
  making remote provider calls or exposing credential values.
- [x] Display structured provider-reported quota limit, remaining, used,
  resource, and reset data when exposed in headers or documented response bodies.
- [x] Automatic passive-intelligence rate-limit handling with a bounded,
  operator-configured `Retry-After` wait.
- [x] Offline integration diagnostics (`enumscan doctor`) that check local
  configuration and required environment-variable presence without exposing
  secrets, calling a provider, validating credentials, or claiming quota.
- [x] Integration API-contract update checker using configured version pins and
  provider deprecation, sunset, and selected-version response signals.

---

# 28. Secrets Management

- [x] Environment variable support.
- [x] Encrypted configuration file.
- [x] OS Keychain support.
- [x] Windows Credential Manager.
- [x] macOS Keychain.
- [x] Linux Secret Service.
- [x] HashiCorp Vault integration.
- [x] Kubernetes Secrets support.
- [x] AWS Secrets Manager.
- [x] Azure Key Vault.
- [x] GCP Secret Manager.
- [x] Secret rotation support.

---

# 29. Projects & Workspaces

- [x] Multiple projects.
- [x] Per-project scope.
- [x] Per-project integrations.
- [x] Per-project API keys.
- [x] Per-project reports.
- [x] Per-project findings.
- [x] Per-project dashboards.
- [x] Per-project scan history.
- [x] Archive projects.
- [x] Import/export projects.

---

# 30. Scan Profiles

- [x] Quick profile application in the engine.
- [x] Standard profile application in the engine.
- [x] Exhaustive profile application in the engine.
- [x] External Infrastructure profile application in the engine.
- [x] Internal Network profile application in the engine.
- [x] Web Application profile application in the engine.
- [x] API Assessment profile application in the engine.
- [x] Active Directory profile application in the engine.
- [x] Kubernetes profile application in the engine.
- [x] Cloud Infrastructure profile application in the engine.
- [x] Bug Bounty profile application in the engine.
- [x] Compliance profile application in the engine.
- [x] Custom template application in the engine.

---

# 31. Frontend

## Backend

- [x] REST API.
- [x] GraphQL API.
- [x] WebSocket events.
- [x] Authentication.
- [x] API tokens.
- [x] Role-based authorization.

## Dashboard

- [x] React frontend.
- [x] Dashboard overview.
- [x] Asset explorer.
- [x] Service explorer.
- [x] Vulnerability explorer.
- [x] Screenshot gallery backed by captured image artifacts.
- [x] Timeline viewer.
- [x] Scan history explorer.
- [x] Asset search.
- [x] Saved filters.
- [x] Dark mode.
- [x] Light mode.

## Visualization

- [x] Attack surface graph.
- [x] Attack path graph.
- [x] Technology graph.
- [x] Asset relationship graph.
- [x] Certificate graph.
- [x] Cloud relationship graph.
- [ ] Interactive Neo4j visualization.

---

# 32. Live Monitoring

- [x] Persisted scheduler activity and module-run snapshots.
- [x] Persisted module activity log stream.
- [x] Worker statistics.
- [x] Queue statistics.
- [x] Evidence-based completed-module throughput metrics.
- [x] Evidence-based ETA for currently queued scheduler work when persisted
  completion-rate data exists; it is omitted when uncertain and notes that new
  discovered events can extend the estimate.
- [x] Persisted live logs.
- [x] Cooperative scan pause/resume at event and module boundaries, driven by
  persisted scan state. In-flight module operations are allowed to finish.
- [x] Live finding SSE stream backed only by persisted scan findings, with
  dashboard wiring and client-side ID deduplication.

---

# 33. Search Engine

- [x] Global search.
- [x] Asset search.
- [x] Service search.
- [x] Technology search.
- [x] Certificate search.
- [x] Secret search.
- [x] Finding search.
- [x] Screenshot search.
- [x] Graph search.
- [x] Saved searches.

---

# 34. Timeline & Change Tracking

- [x] Host timeline.
- [x] Service timeline.
- [x] Certificate timeline.
- [x] Technology timeline.
- [x] Vulnerability timeline.
- [x] Secret timeline.
- [x] Configuration drift detection.
- [x] Daily change reports.
- [x] Weekly summaries.

---

# 35. Multi-User

- [ ] User accounts.
- [ ] Authentication.
- [ ] Role-based access control.
- [ ] Organizations.
- [ ] Teams.
- [ ] Audit logging.
- [ ] API tokens.
- [ ] Session management.
- [ ] SSO support.

---

# 36. Knowledge Graph

- [x] Asset relationship engine.
- [x] Technology relationships.
- [x] Secret relationships.
- [x] Identity relationships.
- [x] Trust relationships.
- [x] Cloud resource relationships.
- [x] Certificate relationships.
- [x] Attack-path relationships.
- [x] Business application relationships.
- [x] Query engine.
- [x] Graph explorer.

---

# 37. Plugin Marketplace

- [x] Marketplace server.
- [x] Plugin discovery.
- [x] Plugin search.
- [x] Plugin ratings.
- [x] Plugin versioning.
- [x] Plugin signing.
- [x] Plugin verification.
- [x] Plugin updates.
- [x] One-click installation.
- [x] Community plugins.

---

# 38. Enterprise Features

- [x] Multi-node scanning.
- [x] Distributed workers.
- [x] Remote agents.
- [x] Job scheduler.
- [ ] HA coordinator.
- [ ] Horizontal scaling.
- [x] Scan load balancing.
- [ ] Agent auto-registration.
- [x] Centralized reporting.

---

# 39. Performance

- [x] Bounded adaptive worker pools wired into the actual scheduler. They are
  explicit opt-in, scale between configured minimum and maximum worker counts
  from observed module duration, persist live capacity telemetry, and preserve
  existing rate limits and fixed-concurrency defaults.
- [x] Connection pooling for configured external stores.
- [x] HTTP keep-alive connection pooling integrated into HTTP modules.
- [x] HTTP/2 multiplexing enabled for HTTP modules.
- [x] Bounded Bloom-assisted exact event deduplication in the scan pipeline.
- [x] Scan deduplication.
- [x] Bounded persistent cache across process restarts for parsed local signature rules.
- [x] Bounded HTTP body-reader buffer pool integrated into the scan pipeline.
- [x] Database indexing.
- [x] Representative large-scale event-pipeline benchmark suite.

---

# 40. Release Roadmap

## v1.0 — Enumeration Engine

- [x] Core engine
- [x] Discovery
- [x] Port scanning
- [x] Service fingerprinting
- [x] HTTP enumeration
- [x] Reporting
- [x] Plugin SDK

## v2.0 — Asset Intelligence Platform

- [x] Historical inventory
- [x] Differential scanning
- [x] REST API
- [x] Dashboard
- [x] Correlation engine
- [x] Knowledge graph
- [x] Risk engine

## v3.0 — Autonomous Recon Platform

- [x] Distributed scanning
- [x] Continuous monitoring
- [x] Production threat-intelligence integrations
- [x] AI-assisted analysis
- [x] Knowledge graph expansion
- [ ] Enterprise features

---

# 41. Unimplemented Feature Backlog — Easiest to Hardest

> This historical section is retained for audit context. `OPEN_WORK.md` is the
> source of truth for completion status. An
> item being low effort does **not** authorize unsafe scanning. Items in the
> final tier need a separate safety policy, explicit credentials, and focused
> authorization before implementation.

## Tier 1 — Small, self-contained improvements

All originally listed Tier 1 improvements are implemented. Scan responses are
intentionally not cached, because enumeration evidence must remain fresh.

## Tier 2 — Bounded feature and integration work

- [x] Opt-in in-memory cookie-jar support for scoped HTTP enumeration.
- [x] Add authenticated crawling with an explicit environment-supplied session
  cookie and per-engagement opt-in. No login, credential guessing, or cookie
  persistence is performed.
- [x] Native bounded directory enumeration with 404/wildcard baselining.
- [x] Opt-in HTTP/2-protobuf gRPC reflection service enumeration.
- [x] Scoped DNS record collection: SOA, NS, MX, TXT, CAA, SRV, CNAME, A, and AAAA.
- [x] Bounded offline tcpdump/tshark TCP-trait import for heuristic OS-family
  hints; no capture traffic is generated by this feature.
- [x] Add a browser screenshot worker and artifact retention, then enable the
  screenshot gallery backed only by captured image artifacts.
- [x] Opt-in, scoped HTTP/3/QUIC transport confirmation for literal IP targets.
- [x] Opt-in local browser-wrapper rendering with bounded, checksum-verified
  PNG artifact retention and gallery serving. The wrapper must enforce the
  engagement's browser-network policy.
- [x] Offline scoped historical URL ingestion from operator-provided exports.
- [x] Add deterministic, evidence-only executive and technical report summaries.
- [x] Add deterministic, evidence-backed risk rationale and safe next
  enumeration recommendations; no exploitation or AI claims are made.
- [x] Add an explicit loopback-only Ollama advisory command based on local,
  deterministic evidence summaries; its output remains unverified text.
- [x] Add bounded evidence-relationship narratives to triage output. They
  preserve verification state and explicitly avoid claiming reachability,
  compromise, or exploitability.
- [x] Add explicit, bounded HTTPS webhook delivery of an evidence-only scan
  summary; redirects are refused and no automatic delivery occurs during scans.
- [x] Add explicit Slack incoming-webhook delivery of a compact evidence
  summary under the same HTTPS and redirect safeguards.
- [x] Add explicit SMTP email delivery of a compact evidence summary with
  STARTTLS required outside localhost and password read from the environment.
- [x] Add an explicit opt-in `scan.completed` webhook subscription. Delivery
  uses the bounded webhook transport and cannot change a healthy scan result.
- [x] Persisted module-run log stream plus scheduler worker, queue, module, and
  throughput snapshots. ETA remains separate work.
- [x] Evidence-backed exposure-chain correlation from persisted findings and assets.
- [x] Add a read-only, fixed-query, scan-scoped interactive Neo4j graph view
  to the dashboard. It is available only when Neo4j sync is configured.
- [x] Safe protocol-specific Cassandra OPTIONS capability, ClickHouse ping,
  InfluxDB health/version, Podman version, and containerd health enumeration.
- [x] Add offline provider diagnostics (`enumscan doctor`) for configured
  passive-intelligence sources and credential-presence preflight.
- [x] Add bounded per-provider pacing, duplicate request suppression, and
  HTTP-429 `Retry-After` compliance for passive-intelligence sources.
- [x] Add local provider capability discovery and dashboard/API readiness
  status; it does not assert remote health, key validity, or quota.
- [x] Add the remaining provider framework mechanics: operator-configured
  enable/disable beyond source selection, provider-specific API-key validation,
  full quota discovery, and update checks. Explicit remote
  reachability/rejection/rate-limit diagnostics are implemented for supported
  credentialed sources.
- [x] Add individually tested providers: VirusTotal, Shodan, Censys,
  SecurityTrails, FOFA, Hunter.io, WhoisXML API, Have I Been Pwned, GitHub,
  GitLab, DNSDB, and CIRCL CVE Search. This also completes the production
  credential-validation items in Passive Intelligence.

## Tier 3 — Major platform and release engineering

- [ ] Integrate PostgreSQL as a selectable, fully migrated operational datastore.
  PostgreSQL is selectable for normal scans through the shared runtime-store
  contract, with a serialized migration ledger, bounded pool, distributed
  evidence ingestion, and CI integration coverage. Final production field
  validation and PostgreSQL-native backup/restore runbooks remain required.
- [x] Integrate optional Neo4j synchronization as a real configured backend.
  Sync is explicit, uses the configured endpoint and environment-supplied
  password, transfers only persisted assets/findings, and has a fixed-query,
  scan-scoped read view.
- [x] Add bounded adaptive worker pools to the actual scheduler, with explicit
  operator opt-in and persisted capacity telemetry.
- [x] Add multi-node/distributed scanning, remote agents, queue-based load
  distribution, and centralized reporting. The authenticated coordinator uses
  durable bounded leases, authorization/config-digest enforcement, Ed25519
  proof of possession, durable replay nonces, lease-owner-only evidence
  ingestion, and completion. Remote coordinators require TLS; horizontally
  scaled agents compete atomically for queued jobs.
- [ ] Add active/passive HA coordinator failover. This depends on completing
  the selectable PostgreSQL operational-store migration.
- [x] Add bounded continuous monitoring for explicit, scope-locked authorized
  configurations. The `monitor` command requires opt-in, a 5–1440 minute
  cadence, and a finite 1–1000 run limit; it persists each scan normally and
  never schedules itself in the background.
- [x] Add authenticated application-level datastore encryption at rest for
  persisted scan evidence, with environment-supplied AES-256 keys, atomic
  plaintext migration, and fail-closed key verification.
- [x] Add production secret-manager support:
  OS keychain, Windows Credential Manager, macOS Keychain, Linux Secret
  Service, HashiCorp Vault, Kubernetes Secrets, AWS Secrets Manager, Azure Key
  Vault, GCP Secret Manager, and secret rotation.
  The environment manager remains read-only. Explicitly configured native OS
  keychain, Vault KV v2, Kubernetes, AWS SigV4, Azure, and GCP adapters perform
  real reads, writes, and rotation without fallback; projected token files are
  reread on every request.
  Authenticated AES-256-GCM encrypted SQLite backup artifacts are available
  through an explicit environment-supplied key. Live sensitive SQLite evidence
  fields are encrypted and authenticated before persistence, and its key can
  be resolved through the configured secret manager. Existing SQLite, backup,
  report, advisory, and screenshot output
  directories are actively restricted to owner-only permissions when Enumscan
  writes them; this complements, but does not replace, encrypted storage.
- Add identity: user accounts, session management, organizations, teams, SSO,
  and broader audited who-ran-what records. Basic opt-in environment-supplied
  API tokens, server-assigned viewer/analyst/admin authorization, and durable
  audit records for state-changing API requests are implemented; authorized
  admins can retrieve recent records through the local API and reload an
  environment-supplied token mapping for rotation. They are not a replacement
  for a multi-user identity provider.
- [x] Add the trusted plugin marketplace: server, discovery/search, ratings,
  versioning, signing/verification, updates, one-click installation, and
  community plugins. This includes real gRPC and Lua plugin runtimes. SDK
  manifests are not auto-loaded by scans, and registry queries require an
  explicitly configured HTTPS endpoint. Lua isolation is capability-based;
  OS-level sandboxing remains a separate deployment task.
- [x] Complete release engineering beyond baseline CI: security scanning, signed
  automatic releases, container publishing, supported-platform validation, and
  production threat-intelligence operations. Hosted Linux/macOS/Windows jobs
  run the full suite and native CLI; protected-environment publication emits
  signed binaries, SBOMs, multi-architecture images, and provenance
  attestations. Scheduled, opt-in NVD/CISA KEV/FIRST EPSS deltas include source
  checksums and attested provenance for reviewed production import.

## Tier 4 — Explicitly safety-gated or out of scope for normal enumeration

These must stay unchecked unless the product gains an explicit authorization
model, credentials where needed, rate/impact controls, and dedicated tests.

The shared active-testing authorization prerequisite is now implemented:
intrusive checks are disabled by default and require an expiring authorization,
operator identity, environment-held acknowledgement, per-technique allowlist,
bounded per-host requests/concurrency/delay, normal target-scope enforcement,
and a durable scan audit event. Individual items below remain unchecked until
their probe implementations and focused safety tests are complete.

- Idle and decoy scanning (third-party involvement or spoofed traffic).
- Active TLS vulnerability verification for Heartbleed, ROBOT, CRIME, and
  BREACH.
- Active web vulnerability payload testing for SQLi, XSS, SSRF, LFI/RFI, XXE,
  SSTI, host-header injection, request smuggling, and prototype pollution.
- OOB interaction listener work for blind SSRF/RCE detection.
- Credentialed SSH/WinRM scanning and authenticated Active Directory
  enumeration.
- Kerberoasting target discovery, Kerberos pre-auth/AS-REP checks, and LAPS
  detection/ACL auditing.
- SMB anonymous/share-permission auditing; SSH authentication-method/key
  collection; FTP anonymous/writable-directory checks; SMTP VRFY/EXPN/open
  relay testing; and full SNMP MIB walks.
- Kubernetes-secret retrieval, Docker Compose-file retrieval, and cloud IMDS
  reachability auditing.
- DNS AXFR testing, DNSSEC NSEC/NSEC3 zone walking, and DNS cache snooping.

## Duplicated roadmap summaries

The unchecked v3.0 roadmap entries — Distributed Scanning, Continuous
Monitoring, Production Threat-Intelligence Integrations, AI-Assisted Analysis,
and Enterprise Features — are summaries of Tiers 2 and 3 above, not separate
work items.

---

# 42. Productization and Adoption Gaps

This section captures the gaps identified during the application-wide product,
usability, UI/UX, reliability, and adoption review. Completion means satisfying
the acceptance criteria stated beneath each item, not merely adding a type,
configuration field, mock, or placeholder.

## P0 — Trust, operability, and adoption blockers

- [x] Publish a single generated capability manifest that identifies every
  feature as `implemented`, `experimental`, `gated`, `planned`, or
  `intentionally_excluded`.
  - Generate it from code-owned metadata rather than manually duplicating the
    roadmap.
  - Expose it through `enumscan capabilities`, JSON output, the API, and the
    documentation build.
  - Include required privileges, credentials, supported platforms, network
    effects, and relevant configuration keys.
- [x] Reconcile the roadmap with the actual implementation.
  - Move completed release history into `CHANGELOG.md`.
  - Keep future work in `OPEN_WORK.md` and current limitations in
    `LIMITATIONS.md`.
  - Remove or annotate stale early unchecked entries that conflict with later
    completed tier entries.
  - Add a CI check that detects contradictory feature status declarations.
- [ ] Complete production PostgreSQL recovery validation.
  - PostgreSQL is selectable for normal scans through the backend-neutral
    runtime store, including scheduler, modules, API, reporting, inventory,
    distributed jobs, audit records, retention, migration ledger, and
    application-level evidence encryption.
  - CI exercises migrations, core evidence, distributed evidence, and encrypted
    evidence against an ephemeral PostgreSQL service.
  - The remaining work is PostgreSQL-native backup/restore, rollback,
    connection-exhaustion and transaction-conflict exercises, supported-version
    policy, and production-shaped recovery validation; track it only in
    `OPEN_WORK.md`.
- [ ] Complete active/passive HA coordinator failover tracked in Tier 3.
  - Use datastore-backed leadership with fencing and bounded lease renewal.
  - Demonstrate that two coordinators cannot concurrently own the same work.
  - Add failover, network-partition, clock-skew, and process-crash tests.
- [ ] Establish a repeatable real-world validation program.
  - Define small, medium, and large authorized test environments covering
    IPv4, IPv6, lossy networks, HTTP-heavy targets, and mixed services.
  - Run prolonged scans and publish sanitized duration, throughput, memory,
    database-growth, retry, and false-positive results.
  - Add regression thresholds and retain comparable benchmark artifacts in CI.
- [ ] Ship straightforward end-user installation paths.
  - Publish versioned archives and documented verification commands.
  - Add at least Homebrew, Debian/RPM, and Winget or Scoop packaging.
  - Test clean installation, upgrade, rollback, and uninstall on each supported
    operating system.
  - Ensure packages use the same signed release provenance as raw binaries.
  - Versioned signed Linux/macOS archives, a Windows ZIP, Debian/RPM packages,
    and Homebrew/Scoop release definitions are generated and validated in
    release CI. Official package-manager publication and clean-install,
    upgrade, rollback, and uninstall tests on every supported operating system
    remain required before this P0 item can be checked.
- [x] Add `enumscan validate-config` and `enumscan capabilities` commands.
  - Validation must perform no target or provider network requests.
  - Report resolved profile, enabled modules, requested privileges, outbound
    destinations, missing environment variables, effective limits, and active
    safety gates.
  - Support human-readable and stable JSON output with secret redaction.
- [x] Replace runtime CDN dependencies in the dashboard.
  - Build and embed pinned React/runtime/font assets during release creation.
  - Remove in-browser Babel and public CDN requirements.
  - Verify the complete dashboard works offline with a restrictive Content
    Security Policy.
- [x] Introduce a maintainable frontend build and test pipeline.
  - Split the large embedded dashboard source into versioned components.
  - Add linting, type checking, unit tests, and production asset bundling.
  - Keep generated embedded assets deterministic and covered by release builds.
- [ ] Complete a formal dashboard accessibility and usability pass.
  - Meet WCAG 2.2 AA for contrast, keyboard access, focus order, labels, tables,
    dialogs, streaming updates, and reduced motion.
  - Test empty, loading, permission-denied, disconnected, partial-scan, and
    high-volume states.
  - Validate desktop, tablet, and narrow-screen layouts with screenshot tests.
  - The dashboard now provides a skip link, visible keyboard focus, reduced-motion
    handling, labelled controls, keyboard-operable graph/table selections, an
    accessible saved-query dialog, and a live disconnected-state message. Formal
    WCAG validation and the complete state/device test matrix remain required.
- [ ] Finish each Tier 4 runner before presenting it as available.
  - Require the existing expiring per-technique authorization gate at the
    final network-action boundary.
  - Add protocol fixtures, request/impact-budget tests, cancellation, redaction,
    audit, and negative authorization tests for every runner.
  - Make the capability manifest distinguish an accepted authorization name
    from an executable probe.
- [ ] Add OS-level isolation for untrusted plugins.
  - Define supported sandbox backends per operating system and fail closed when
    the requested isolation level is unavailable.
  - Restrict filesystem, process, network, CPU, memory, and execution time.
  - Add escape-resistance tests and document the residual trust model.

## P1 — Operator experience and enterprise readiness

- [~] Add a guided first-run and engagement setup wizard.
  - Implemented: `make engagement-wizard` / `enumscan engagement-wizard` collect
    a single scope, profile, and written authorization, then write a new
    mode-`0600` safe-enumeration configuration without overwriting a file.
  - Remaining: assessment-template selection, dependency checks, an
    effective-plan summary, and an explicit pre-run confirmation.
- [ ] Restructure CLI help into discoverable command groups.
  - Provide `enumscan help <command>`, examples, documented exit codes, and
    shell completion for Bash, Zsh, Fish, and PowerShell.
  - Keep noninteractive JSON errors stable for automation.
- [~] Add an interactive dashboard engagement wizard.
  - Implemented: **New engagement** downloads a server-validated, scope-locked
    YAML plan through the authenticated API without writing to the coordinator
    or exposing credentials.
  - Remaining: preview modules, ports, request estimates, external providers,
    privileges, and safety warnings before execution.
- [ ] Expand the TUI beyond read-only scan history.
  - Add findings, assets, module health, logs, filtering, and report generation.
  - Keep scan-starting or mutation actions behind explicit confirmation and
    authorization checks.
- [ ] Add production identity and tenant boundaries.
  - Implement users, sessions, organizations, teams, OIDC/SAML SSO, and scoped
    service accounts.
  - Enforce tenant ownership in every datastore query, stream, report,
    screenshot, graph, distributed job, and audit record.
  - Add authorization-matrix and cross-tenant isolation tests.
- [ ] Complete credentialed assessment infrastructure.
  - Resolve credentials through configured secret managers with per-engagement
    references, least-privilege documentation, rotation, and revocation.
  - Never persist supplied credentials or retrieved secret contents.
  - Add protocol-specific fixtures and proof that failure paths remain redacted.
- [ ] Harden distributed operation under failure.
  - Add agent reconnect/resume, bounded retry policy, coordinator backpressure,
    duplicate-evidence idempotency, graceful drain, and safe agent upgrades.
  - Exercise packet loss, slow agents, expired leases, partial uploads, and
    coordinator restart in automated tests.
- [ ] Add production observability exports.
  - Provide Prometheus/OpenMetrics metrics and OpenTelemetry traces for queue,
    module, datastore, provider, agent, and notification behavior.
  - Exclude target content, credentials, cookies, tokens, and sensitive finding
    evidence from labels and spans.
  - Publish alerting and capacity-planning examples.
- [ ] Define and test data lifecycle controls.
  - Add configurable retention for scans, raw events, screenshots, logs, audit
    records, provider cache, and reports.
  - Support legal hold, scoped export, verified purge, and storage-usage preview.
  - Audit destructive actions and test encrypted backup interaction.
- [ ] Publish a disaster-recovery procedure and exercise it automatically.
  - Cover SQLite and PostgreSQL backup, restore, key recovery, corruption
    detection, version compatibility, and recovery-time expectations.
  - Run scheduled restore tests against production-shaped encrypted artifacts.
- [ ] Add contract tests for every external integration.
  - Pin supported API versions and fixture schemas.
  - Test authentication rejection, quota exhaustion, pagination, retry-after,
    malformed responses, deprecation signals, and provider outages.
  - Ensure provider changes cannot silently produce empty successful scans.
- [ ] Publish a stable OpenAPI specification and supported client workflow.
  - Generate or verify the specification against registered routes and RBAC.
  - Include authentication, pagination, errors, streams, and versioning policy.
  - Add at least one generated-client smoke test.

## P2 — Workflow depth, ecosystem, and product clarity

- [ ] Add assessment/project workflow above individual scan IDs.
  - Group scans, authorization documents, baselines, notes, owners, evidence,
    reports, and remediation status into an engagement lifecycle.
- [ ] Add finding review and remediation workflow.
  - Support assignment, status, severity override with rationale, duplicate
    linking, suppression expiry, retest state, and an immutable history.
- [ ] Add explicit ticketing and collaboration integrations.
  - Start with generic signed webhooks, then add narrowly scoped Jira and GitHub
    issue export with idempotency and field mapping.
  - Require preview and explicit delivery; never send raw secrets.
- [ ] Add signed module-rule and provider-definition updates.
  - Separate data/rule updates from executable plugin updates.
  - Verify signatures, compatibility, rollback, provenance, and an offline
    installation path.
- [ ] Define marketplace governance and community review.
  - Document publisher identity, key rotation, moderation, malicious-package
    response, rating abuse controls, deprecation, and removal.
  - Display verification and permission information before installation.
- [ ] Publish sanitized demonstration assets.
  - Provide a local lab, sample configurations, fixture scan database, example
    reports, dashboard screenshots, and a short end-to-end walkthrough.
  - Ensure every example is reproducible without scanning public systems.
- [ ] Clarify the primary product position and supported use cases.
  - Define the principal audience, supported assessment workflow, explicit
    non-goals, comparison boundaries, and a concise release-readiness statement.
  - Align the README, website/docs, templates, dashboard language, and release
    notes with that position.
