# enumscan TODO

## 1. Foundation

- [x] Create CLI-first Go project structure.
- [x] Add SQLite-backed scan state and asset storage.
- [x] Add constrained YAML config and scan templates.
- [x] Add scope enforcement before scanning.
- [x] Add event-driven scheduler and module interface.
- [x] Add JSON and Markdown reporting.
- [x] Add Python report summary script.

## 2. Core Engine

- [ ] Replace SQLite CLI bridge with a Go SQLite driver when dependencies are available.
- [x] Add resumable scan runs and per-module checkpoints.
- [x] Add structured logging with scan id, module, target, and event id.
- [x] Add global and per-target rate limits.
- [x] Add cancellation and timeout policy per module.

## 3. Discovery

- [ ] Add CIDR expansion.
- [ ] Add reverse DNS lookups.
- [ ] Add passive DNS and certificate transparency importers.
- [ ] Add ASN/RDAP lookup support.
- [ ] Add wildcard DNS detection.
- [ ] Add cloud/CDN/load balancer detection.

## 4. Port Scanning

- [ ] Add full TCP connect scan profile.
- [ ] Add raw SYN scanning where privileges allow.
- [ ] Add UDP scanning for DNS, SNMP, NTP, TFTP, SIP, IKE, RPC, NetBIOS, mDNS, SSDP, LDAP, Kerberos, and RADIUS.
- [ ] Add banner grabbing for open TCP services.
- [ ] Add adaptive timing based on latency and failures.
- [ ] Add safe scan profiles: quick, standard, exhaustive.

## 5. Service Fingerprinting

- [ ] Add protocol probes for SSH, FTP, SMTP, DNS, SMB, LDAP, databases, Redis, Elasticsearch, and Kubernetes.
- [ ] Normalize service names, versions, and CPE candidates.
- [ ] Store evidence for every fingerprint.

## 6. HTTP, TLS, and Crawling

- [ ] Add TLS certificate collection and SAN extraction.
- [ ] Add TLS version and cipher enumeration.
- [ ] Add security header checks.
- [ ] Add robots.txt and sitemap parsing.
- [ ] Add recursive crawler with depth, auth, cookies, and scope controls.
- [ ] Add JavaScript endpoint and secret extraction.
- [ ] Add API discovery for OpenAPI, Swagger, GraphQL, SOAP, REST, and gRPC.
- [ ] Add screenshots for web pages and high-value panels.

## 7. Specialized Enumeration

- [ ] Add SMB enumeration through a proven external engine or library.
- [ ] Add LDAP and Active Directory authenticated enumeration.
- [ ] Add SNMP MIB walking with safe community handling.
- [ ] Add cloud asset checks for AWS, Azure, GCP, DigitalOcean, and Cloudflare.
- [ ] Add container and Kubernetes exposure checks.
- [ ] Add database exposure and authentication checks.

## 8. Vulnerability and Correlation

- [ ] Add finding schema fields for CWE, CVE, CVSS, EPSS, KEV, references, and remediation.
- [ ] Add NVD feed mirror/import workflow.
- [ ] Add CPE matching with backport-aware confidence levels.
- [ ] Add Nuclei/OpenVAS/Nessus integration points.
- [ ] Add correlation engine for attack paths.
- [ ] Add graph export for Neo4j.
- [ ] Add SARIF export for CI/CD.

## 9. Plugin SDK

- [ ] Define stable plugin manifest format.
- [ ] Add gRPC plugin host.
- [ ] Add Lua script plugin runner for lightweight checks.
- [ ] Add plugin permission model and event subscriptions.
- [ ] Add sample external plugin.

## 10. Testing and Release

- [ ] Add unit tests for config parsing, scope checks, store queries, and scheduler behavior.
- [ ] Add local integration tests using loopback HTTP fixtures.
- [ ] Add CI workflow for formatting, tests, and static analysis.
- [ ] Add release builds for Linux, macOS, and Windows.
- [ ] Add operator documentation and authorized-use guidance.
