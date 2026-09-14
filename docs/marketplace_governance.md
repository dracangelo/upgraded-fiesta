# Marketplace Governance & Trust Architecture

Enumscan provides an extensible plugin and rule ecosystem designed for enterprise cybersecurity assessments. To protect operator infrastructure and maintain evidentiary integrity, all marketplace distributions are subject to strict governance, cryptographic verification, and abuse mitigation controls.

---

## 1. Publisher Trust Tiers

Publishers must register verified signing keys before distributing modules or plugins.

| Tier | Description | Requirement |
| --- | --- | --- |
| `official` | Maintained directly by the core Enumscan engineering team. | Hardware security module (HSM) backed Ed25519 signing keys pinned directly into release binaries. |
| `verified` | Security vendors and enterprise partners vetted through code review and identity verification. | Identity verification, contact SLA, and cryptographic key pinning with automated audit logging. |
| `untrusted` | Community and third-party contributions. | Permitted only when `--allow-community-plugins` is explicitly set by the operator. Sandboxed by default. |
| `revoked` | Compromised, abusive, or malicious publisher identities. | Blocked unconditionally across all deployments. Installation and execution rejected. |

---

## 2. Cryptographic Verification & Key Pinning

- **Ed25519 Signatures**: Every plugin package manifest contains an SHA256 digest of the distribution bundle signed with the publisher's registered private key.
- **Offline Signature Validation**: The runtime verifies signatures against locally pinned public keys prior to extracting or executing any plugin code.
- **Zero Auto-Execution**: Discovered plugins are never automatically loaded or executed without operator confirmation and cryptographic verification.

---

## 3. Revocation Lists & Security Advisories

When a vulnerability or backdoor is discovered in a published plugin or version:
1. A **Revocation Entry** is published to the central Certificate/Plugin Revocation List (`CRL`).
2. The entry records the specific `plugin_id`, target `version` (or all versions if omitted), reason, and external advisory identifier (e.g., `ADV-2026-001`).
3. During runtime installation or startup verification, any match against the revocation list halts execution and alerts the operator:
   ```
   error: plugin package or version is revoked: revoked: Critical vulnerability discovered (advisory: ADV-2026-001)
   ```

---

## 4. Community Reviews & Ratings

Operators and security researchers can submit structured feedback:
- **Ratings**: 1 to 5 stars.
- **Qualitative Reviews**: Operational notes regarding performance, stability, or false-positive rates.
- **Reputation Aggregation**: The governance engine continuously aggregates scores to provide transparency before installation.

---

## 5. Abuse Handling & Reporting

Suspected malicious behavior or unauthorized telemetric activity can be reported to `security@enumscan.local`. Security incident responders will immediately:
1. Issue an emergency revocation entry.
2. Demote the publisher to `revoked` tier.
3. Push an updated revocation list across all connected registries.
