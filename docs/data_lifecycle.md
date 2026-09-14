# Data Lifecycle Controls & Retention Governance

Enumscan implements data lifecycle governance supporting enterprise data retention policies, legal holds, data classification tiers, and tamper-evident purge audits.

## 1. Evidence Classification Tiers

| Classification | Sensitivity | Examples | Handling & Protection |
| --- | --- | --- | --- |
| `public` | Low | DNS records, public IPs, HTTP response headers | Unrestricted export |
| `internal` | Medium | Private IP ranges, hostnames, infrastructure topologies | Tenant-scoped access |
| `confidential` | High | Software versions, CVE correlations, open ports, configurations | Encrypted at rest, RBAC required |
| `restricted` | Critical | Credential audit results, private keys, API tokens | Zeroized in memory, strictly redacted in all exports |

---

## 2. Per-Project Retention Policies

Retention policies define automatic data pruning based on age while preserving a minimum baseline of scans:

```go
policy := store.RetentionPolicy{
    ProjectID:    "corp-core",
    MaxAge:       90 * 24 * time.Hour, // Retain scans for 90 days
    MinScansKeep: 5,                   // Never delete the last 5 scans
}
```

---

## 3. Legal Hold Protection

Scans subject to ongoing security investigations, incident response, or regulatory audits can be locked under an active **Legal Hold**:

- When `legal_hold` is enabled, automated lifecycle purges are permanently blocked from deleting the scan run and all related child records (assets, findings, events, checkpoints).
- Releasing a legal hold requires explicit administrative action and is logged in the audit ledger.

---

## 4. Tamper-Evident Purge Audit

Every data purge operation records an entry into the immutable `purge_audit_log` table capturing:
- Unique purge execution ID
- Exact timestamp of deletion
- Number of scan runs, assets, and findings purged
- Justification / retention rule applied
- Operator or background task identity
