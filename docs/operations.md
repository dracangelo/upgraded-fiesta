# Operations guide

## Datastores

SQLite is the default local datastore. PostgreSQL is selectable through
`database.driver: postgres`, an environment-held DSN, and bounded pool limits.
Run `postgres-migrate` before production use.

Application-level authenticated encryption protects configured sensitive
fields. Keys come from an environment variable, OS keyring, or configured
secret manager. Encrypted backup and confirmed restore are separate commands.

## Secret managers

Enumscan supports explicit Vault, AWS Secrets Manager, Azure Key Vault, Google
Cloud Secret Manager, and Kubernetes Secret backends. HTTPS is required except
for loopback development. Workload credentials and tokens remain outside YAML.

Use `secret-check` for a non-value readiness check and `secret-set` or
`secret-rotate` only as explicit operator actions.

## Continuous monitoring

Monitoring is disabled by default and runs only through the `monitor` command.
It retains the same scope and authorization for every bounded iteration and
stops at `monitoring.max_runs`.

## Distributed scanning

Coordinator jobs contain a scan ID, authorization reference, configuration
SHA-256 digest, lease state, and attempt count. Agents are enrolled with Ed25519
public keys; signed timestamps and one-use nonces prevent replay. Agents execute
only a local configuration matching the job digest and authorization.

Remote coordinators require HTTPS. Start an enrolled agent with:

```sh
enumscan -config configs/agent.yaml distributed-agent \
  -agent agent-east -coordinator https://coordinator.example:8080
```

The private key is read from `ENUMSCAN_AGENT_PRIVATE_KEY` unless another
approved mechanism is explicitly configured.

## Neo4j and notifications

Neo4j synchronization and webhook/Slack/email delivery are explicit outbound
operations. Remote Neo4j and webhook endpoints require HTTPS. The automatic
webhook subscription sends only after a healthy completed scan.

## Containers and releases

`make image` builds the local non-root image. Mount a private configuration and
writable `/data` volume. `make build-cross`, `make reproducible`, and
`make checksums` create the release artifacts.

Release automation performs hosted platform tests, security scans, SBOM and
provenance generation, signed checksums, and approved multi-architecture GHCR
publication. Production publication is gated by the `production-release`
environment and `APPROVED_CONTAINER_PUBLISH=true`.

## Production checklist

- Use an engagement-specific configuration and database.
- Replace every template placeholder.
- Set conservative concurrency, timeout, and pacing values.
- Keep credentials in environment/workload identity/secret managers.
- Require API authentication and TLS for non-loopback access.
- Encrypt live sensitive data and backups with separately managed keys.
- Verify release attestations and image signatures.
- Back up, restore-test, monitor disk usage, and retain audit records.

