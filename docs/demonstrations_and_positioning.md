# Demonstrations, Safe Positioning & Operational Boundaries

Enumscan is an authorized enterprise attack surface enumeration and security intelligence pipeline. It is engineered specifically for defensive security teams, red teams operating under written rules of engagement, and compliance auditors.

---

## 1. Product Positioning & Purpose

- **Intended Use**: Defensive security posture evaluation, attack surface discovery, asset inventory correlation, and pre-production security validation.
- **Evidentiary Integrity**: Evidence gathered is hashed, timestamped, and stored in tamper-evident datastores with full cryptographic custody tracking.
- **Safety by Default**: Enumscan operates in bounded, non-destructive reconnaissance modes unless high-tier active testing is explicitly authorized with signed mandates.

---

## 2. Strict Operator Boundaries

All scanning activities must respect non-negotiable boundaries:

1. **Pre-Authorization Requirement**: Operators must supply an authorization reference (`--authorization <ref>`) prior to launching scans.
2. **Deterministic Scoping**: Scans strictly target addresses within the declared IP, CIDR, or hostname boundaries. Out-of-scope packet emissions are rejected by the engine kernel.
3. **Bandwidth & Rate Ceilings**: Default execution profiles enforce conservative requests-per-second (`--rate-limit`) and worker concurrency limits to prevent service disruption on target networks.

---

## 3. Non-Destructive Guarantees & Excluded Behaviors

Enumscan explicitly prohibits and excludes behaviors that could disrupt production systems:

- **No Denial of Service**: The engine does not emit high-volume syn-floods, amplification attacks, or memory-exhaustion payloads.
- **No Decoy / Spoof Scanning**: Spoofed source IP scanning (which involves uninvolved third parties) is strictly excluded.
- **No Automated Exploitation**: Finding verification gathers non-intrusive evidentiary indicators (version banners, response headers, unauthenticated probes) without executing disruptive exploit payloads.
- **No Production Secret Harvesting**: Excludes scraping credentials from local Docker Compose environments or unverified external repositories.

---

## 4. Sanitized Synthetic Demonstrations

To evaluate the platform, conduct operator training, or integrate CI/CD workflows without generating external network packets, Enumscan includes a synthetic evaluation suite:

- **Documentation Networks**: Utilizes RFC 5737 (`198.51.100.0/24`) and RFC 2606 reserved domains (`*.example.internal`).
- **Pre-Seeded Evidentiary Data**: Generates realistic network assets, service fingerprints (Nginx, OpenSSH, Redis), and vulnerability findings (CVE-2023-48795, missing HSTS, exposed databases).
- **Zero Sockets**: Operates completely in-memory or on local SQLite/PostgreSQL stores with zero network packets emitted.
