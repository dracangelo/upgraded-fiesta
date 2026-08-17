# Recon OS TODO

> Goal: Build a modular, event-driven reconnaissance and enumeration platform for authorized security assessments.

---

# 1. Foundation

- [x] Create CLI-first Go project structure.
- [x] Add SQLite-backed scan state and asset storage.
- [x] Add PostgreSQL backend.
- [x] Add optional Neo4j backend.
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
- [ ] Add CSV report export.
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
- [x] Add adaptive worker pools.
- [x] Add distributed scanning.
- [x] Add remote scan agents.
- [x] Add task priority queues.
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
- [x] Store screenshots.
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
- [x] Idle scanning.
- [x] Fragmented packet scanning.
- [x] Decoy scanning.
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
- [x] OS fingerprint improvements.
- [x] TCP/IP stack OS fingerprinting (TTL, TCP window size, option ordering analysis).
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
- [x] HTTP/3 support.
- [x] Favicon fingerprinting.
- [x] WebAssembly analysis.
- [x] SPA route discovery.
- [x] Dynamic rendering.
- [x] SSL/TLS vulnerability checks (Heartbleed, ROBOT, CRIME, BREACH).
- [x] OCSP status checking.
- [x] HPKP (Public Key Pinning) header audit.
- [x] Web Application Manifest (manifest.json) analysis.
- [x] Redirect chain & canonical URL tracking.
- [x] Allowed HTTP Verbs/Methods enumeration (OPTIONS, TRACE, PUT, DELETE).
- [x] Response timing, body-size, compression, and default-error-page profiling.
- [x] Error page & default page fingerprinting.
- [x] Response timing & compression (gzip, brotli, deflate) audit.
- [x] gobuster dirb and other enumeration.

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
- [x] Active Directory.
- [x] SNMP.
- [x] Kubernetes
- [x] Cloud assets
- [x] Databases
- [x] Docker socket detection.
- [x] Docker registry discovery.
- [x] Container runtime enumeration.
- [x] Docker Compose discovery.
- [x] Kubernetes secrets discovery.
- [x] Full DNS Record enumeration (SOA, NS, MX, TXT, CAA, SRV, CNAME).
- [x] DNS Zone Transfer (AXFR) testing & DNSSEC NSEC/NSEC3 zone walking.
- [x] DNS cache snooping.
- [x] SMB share permissions & anonymous session auditing.
- [x] LDAP naming-context discovery from an observed anonymous RootDSE response.
- [x] Kerberoasting target identification (SPN enumeration).
- [x] LAPS (Local Administrator Password Solution) detection & ACL delegation audit.
- [x] SSH host key, cipher suite, and authentication method enumeration.
- [x] FTP writable directory auditing & anonymous login checks.
- [x] SMTP VRFY/EXPN user enumeration and open relay testing.
- [x] SNMP MIB walk for system processes, installed software, network routes, ARP tables, and storage devices.
- [x] Database Engine Enumeration (Cassandra, ClickHouse, InfluxDB, MSSQL, Oracle).
- [x] Podman & Containerd runtime enumeration.
- [x] Cloud Instance Metadata Service (IMDSv1 / IMDSv2) reachability auditing.
- [x] Serverless endpoint identification from observed AWS Lambda, Azure Functions, and GCP Cloud Run/Functions response headers.
- [x] Safe protocol identification for Cassandra, ClickHouse, InfluxDB, Podman, and containerd HTTP endpoints.

---

# 11. Passive Intelligence

- [x] Shodan integration.
- [x] Censys integration.
- [x] SecurityTrails integration.
- [x] FOFA integration.
- [x] VirusTotal integration.
- [x] Wayback Machine integration.
- [x] GitHub code search.
- [x] GitLab search.
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
- [x] Nuclei integration.
- [x] OpenVAS integration.
- [x] Nessus integration.
- [x] KEV correlation.
- [x] EPSS auto-prioritization.
- [x] Exploit availability tracking.
- [x] Misconfiguration engine.
- [x] Detection rules engine.
- [x] Web Vulnerability Engine (SQLi, XSS, SSRF, LFI/RFI, XXE, SSTI, CORS, Host Header Injection, HTTP Request Smuggling, Prototype Pollution).
- [x] CIS Benchmark & Security Hardening compliance checks.
- [x] Credentialed scanning engine (SSH / WinRM authenticated patch & package auditing).
- [x] Local offline NVD JSON feed mirror & version backporting analysis.

---

# 15. Correlation Engine

- [x] Attack path generation.
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
- [ ] Webhooks. //skip for now
- [ ] Slack notifications. // skip for now
- [ ] Email notifications. // skip for now

---

# 19. Plugin SDK

- [x] Plugin manifest.
- [x] gRPC plugins.
- [x] Lua plugins.
- [x] Permissions.
- [x] Event subscriptions.
- [x] Sample plugin.
- [x] Plugin marketplace.
- [x] Plugin signing.
- [x] Plugin sandboxing.
- [x] Hot plugin reload.

---

# 20. Operator Experience

- [x] Web dashboard.
- [x] Live scan progress.
- [x] Asset explorer.
- [x] Graph explorer.
- [x] Screenshot gallery.
- [x] Timeline view.
- [x] Search engine.
- [x] Saved queries.
- [x] Dark mode.

---

# 21. AI Assistance

- [ ] Executive report summaries.
- [ ] Technical report summaries.
- [ ] Finding explanation.
- [ ] Suggested next enumeration steps.
- [ ] Attack path explanation.
- [ ] Risk justification.
- [ ] Local LLM support.

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

- [ ] GitHub Actions.
- [ ] Static analysis.
- [ ] Security scanning.
- [ ] Dependency auditing.
- [ ] Cross-platform builds.
- [ ] Automatic releases.
- [ ] Docker images.

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

- [ ] Encryption at rest for the findings datastore.
- [ ] Secret redaction in generated reports.
- [ ] Secrets manager integration for the tool's own credentialed-scan credentials.
- [ ] Access control and audit log — who ran what scan, when.
- [ ] Evidence chain-of-custody logging per engagement.

---

# 26. Advanced Intelligence & Modern Web

- [ ] Add technology stack fingerprinting (Wappalyzer JSON signature rules matching).
- [ ] Add dynamic tech-aware directory fuzzing module with automatic 404/wildcard detection.
- [ ] Add historical URL harvesting from Wayback Machine, Common Crawl, and OTX (`gau`/`waybackurls`).
- [ ] Add VirusTotal API reputation queries and native `go-yara` static artifact scanning.
- [ ] Add Out-of-Band (OOB) interaction listener client for blind SSRF/RCE detection.
- [ ] Add Kerberos pre-authentication user enumeration and AS-REP roasting checks.
- [ ] Add BloodHound-compatible JSON/graph export for Active Directory findings.
- [ ] Add differential scan engine (comparing DB runs to identify net-new assets and resolved flaws).
- [ ] Add terminal dashboard (TUI) powered by `charmbracelet/bubbletea`.

---

# 27. Integrations

## Integration Framework

- [ ] Build provider abstraction layer.
- [ ] Define integration interface.
- [ ] Add integration lifecycle management.
- [ ] Add integration health checks.
- [ ] Add integration diagnostics.
- [ ] Add integration rate limiting.
- [ ] Add integration caching.
- [ ] Add retry and backoff policies.
- [ ] Add provider capability discovery.

## Bring Your Own API Keys

- [ ] VirusTotal
- [ ] AbuseIPDB
- [ ] Shodan
- [ ] Censys
- [ ] SecurityTrails
- [ ] GreyNoise
- [ ] BinaryEdge
- [ ] FOFA
- [ ] AlienVault OTX
- [ ] URLScan.io
- [ ] Hunter.io
- [ ] WhoisXML API
- [ ] Have I Been Pwned
- [ ] GitHub
- [ ] GitLab
- [ ] DNSDB
- [ ] CIRCL CVE Search

## Integration Management

- [ ] Enable/disable integrations.
- [ ] Validate API keys.
- [ ] Show provider status.
- [ ] Display remaining API quota.
- [ ] Automatic rate-limit handling.
- [ ] Integration diagnostics (`enumscan doctor`).
- [ ] Integration update checker.

---

# 28. Secrets Management

- [ ] Environment variable support.
- [ ] Encrypted configuration file.
- [ ] OS Keychain support.
- [ ] Windows Credential Manager.
- [ ] macOS Keychain.
- [ ] Linux Secret Service.
- [ ] HashiCorp Vault integration.
- [ ] Kubernetes Secrets support.
- [ ] AWS Secrets Manager.
- [ ] Azure Key Vault.
- [ ] GCP Secret Manager.
- [ ] Secret rotation support.

---

# 29. Projects & Workspaces

- [ ] Multiple projects.
- [ ] Per-project scope.
- [ ] Per-project integrations.
- [ ] Per-project API keys.
- [ ] Per-project reports.
- [ ] Per-project findings.
- [ ] Per-project dashboards.
- [ ] Per-project scan history.
- [ ] Archive projects.
- [ ] Import/export projects.

---

# 30. Scan Profiles

- [ ] Quick
- [ ] Standard
- [ ] Exhaustive
- [ ] External Infrastructure
- [ ] Internal Network
- [ ] Web Application
- [ ] API Assessment
- [ ] Active Directory
- [ ] Kubernetes
- [ ] Cloud Infrastructure
- [ ] Bug Bounty
- [ ] Compliance
- [ ] Custom templates.

---

# 31. Frontend

## Backend

- [ ] REST API.
- [ ] GraphQL API.
- [ ] WebSocket events.
- [ ] Authentication.
- [ ] API tokens.
- [ ] Role-based authorization.

## Dashboard

- [ ] React frontend.
- [ ] Dashboard overview.
- [ ] Asset explorer.
- [ ] Service explorer.
- [ ] Vulnerability explorer.
- [ ] Screenshot gallery.
- [ ] Timeline viewer.
- [ ] Scan history.
- [ ] Asset search.
- [ ] Saved filters.
- [ ] Dark mode.
- [ ] Light mode.

## Visualization

- [ ] Attack surface graph.
- [ ] Attack path graph.
- [ ] Technology graph.
- [ ] Asset relationship graph.
- [ ] Certificate graph.
- [ ] Cloud relationship graph.
- [ ] Interactive Neo4j visualization.

---

# 32. Live Monitoring

- [ ] Live scan progress.
- [ ] Module progress.
- [ ] Worker statistics.
- [ ] Queue statistics.
- [ ] Throughput metrics.
- [ ] Estimated completion time.
- [ ] Live logs.
- [ ] Scan pause/resume.
- [ ] Live findings stream.

---

# 33. Search Engine

- [ ] Global search.
- [ ] Asset search.
- [ ] Service search.
- [ ] Technology search.
- [ ] Certificate search.
- [ ] Secret search.
- [ ] Finding search.
- [ ] Screenshot search.
- [ ] Graph search.
- [ ] Saved searches.

---

# 34. Timeline & Change Tracking

- [ ] Host timeline.
- [ ] Service timeline.
- [ ] Certificate timeline.
- [ ] Technology timeline.
- [ ] Vulnerability timeline.
- [ ] Secret timeline.
- [ ] Configuration drift detection.
- [ ] Daily change reports.
- [ ] Weekly summaries.

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

- [ ] Asset relationship engine.
- [ ] Technology relationships.
- [ ] Secret relationships.
- [ ] Identity relationships.
- [ ] Trust relationships.
- [ ] Cloud resource relationships.
- [ ] Certificate relationships.
- [ ] Attack-path relationships.
- [ ] Business application relationships.
- [ ] Query engine.
- [ ] Graph explorer.

---

# 37. Plugin Marketplace

- [ ] Marketplace server.
- [ ] Plugin discovery.
- [ ] Plugin search.
- [ ] Plugin ratings.
- [ ] Plugin versioning.
- [ ] Plugin signing.
- [ ] Plugin verification.
- [ ] Plugin updates.
- [ ] One-click installation.
- [ ] Community plugins.

---

# 38. Enterprise Features

- [ ] Multi-node scanning.
- [ ] Distributed workers.
- [ ] Remote agents.
- [ ] Job scheduler.
- [ ] HA coordinator.
- [ ] Horizontal scaling.
- [ ] Scan load balancing.
- [ ] Agent auto-registration.
- [ ] Centralized reporting.

---

# 39. Performance

- [ ] Adaptive worker pools.
- [ ] Connection pooling.
- [ ] HTTP keep-alive optimization.
- [ ] HTTP/2 multiplexing.
- [ ] Bloom filters.
- [ ] Scan deduplication.
- [ ] Persistent cache.
- [ ] Memory optimization.
- [ ] Database indexing.
- [ ] Large-scale benchmark suite.

---

# 40. Release Roadmap

## v1.0 — Enumeration Engine

- [ ] Core engine
- [ ] Discovery
- [ ] Port scanning
- [ ] Service fingerprinting
- [ ] HTTP enumeration
- [ ] Reporting
- [ ] Plugin SDK

## v2.0 — Asset Intelligence Platform

- [ ] Historical inventory
- [ ] Differential scanning
- [ ] REST API
- [ ] Dashboard
- [ ] Correlation engine
- [ ] Knowledge graph
- [ ] Risk engine

## v3.0 — Autonomous Recon Platform

- [ ] Distributed scanning
- [ ] Continuous monitoring
- [ ] Threat intelligence
- [ ] AI-assisted analysis
- [ ] Knowledge graph expansion
- [ ] Enterprise features
