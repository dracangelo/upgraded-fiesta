# Security model

Enumscan is intended only for explicitly authorized security assessments.

## Core guarantees

- Every scan requires a written authorization reference.
- Every requested and discovered target is constrained by the configured scope.
- Network work is bounded by concurrency, timeout, and pacing controls.
- Potentially sensitive evidence is minimized and redacted.
- Credentials are referenced indirectly and are not written into reports.
- State-changing API requests are role-checked and durably audited.
- Distributed work is digest-bound, signed, leased, and replay-resistant.
- Marketplace packages require a configured HTTPS registry, checksum, and
  Ed25519 signature before installation.

## Trust boundaries

The operator controls configuration, target authorization, credentials, local
storage, plugin trust keys, and external endpoints. Remote targets, provider
responses, imported files, plugin packages, browser output, and agent evidence
are untrusted inputs and are parsed with explicit bounds.

## Safe defaults

Active liveness, UDP, raw sockets, authenticated crawling, screenshots,
third-party providers, outbound notifications, monitoring, remote graph sync,
plugins, and Tier 4 testing are disabled until individually configured.

## Active testing

Tier 4 uses a separate expiring authorization, operator identity,
environment-held acknowledgment, technique allowlist, hard impact ceilings,
and an audit event. A normal scan authorization never implies active-testing
permission. See [Tier 4 active testing](tier4_active_testing.md).

## Reporting security issues

Do not include live credentials, customer target lists, raw secret findings, or
other engagement data in a public issue. Provide the smallest reproducible test
case and rotate any credential that may have been exposed.

For additional design detail, see [threat_model.html](threat_model.html) and
[authorized_use.html](authorized_use.html).

