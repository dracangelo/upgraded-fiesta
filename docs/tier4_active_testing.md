# Tier 4 active testing

Tier 4 contains intrusive checks that can change application state, expose
sensitive data, consume credentials, trigger monitoring, or involve another
system. It is never enabled by an ordinary enumscan authorization reference.

## Current implementation status

The shared authorization gate is implemented and tested. The individual Tier
4 probe runners are not yet connected to scans. Selecting a technique today
authorizes that future runner and creates an audit record; it does not fabricate
a finding or claim that a vulnerability was tested.

| Family | Technique names | Probe runner |
| --- | --- | --- |
| Raw third-party scans | `idle_scan`, `decoy_scan` | Not yet connected |
| TLS | `tls_heartbleed`, `tls_robot`, `tls_crime`, `tls_breach` | Not yet connected |
| Web payloads | `web_sqli`, `web_xss`, `web_ssrf`, `web_lfi_rfi`, `web_xxe`, `web_ssti`, `web_host_header`, `web_request_smuggling`, `web_prototype_pollution` | Not yet connected |
| Out-of-band | `oob_interaction` | Not yet connected |
| Credentialed hosts and AD | `ssh_credentialed`, `winrm_credentialed`, `active_directory_authenticated` | Not yet connected |
| Kerberos and LAPS | `kerberos_roast_discovery`, `kerberos_asrep`, `laps_acl_audit` | Not yet connected |
| Network services | `smb_permission_audit`, `ssh_auth_audit`, `ftp_write_audit`, `smtp_relay_audit`, `snmp_mib_walk` | Not yet connected |
| Container and cloud | `kubernetes_secret_audit`, `docker_compose_audit`, `cloud_imds_audit` | Not yet connected |
| DNS | `dns_axfr`, `dnssec_zone_walk`, `dns_cache_snoop` | Not yet connected |

## Authorization contract

All of the following conditions must hold before enumscan accepts an active
testing configuration:

1. `scope.authorization` identifies the written engagement authorization.
2. `active_testing.enabled` is `true`.
3. `authorization_expires` is a future RFC3339 timestamp.
4. `operator` identifies the accountable operator.
5. `allowed_techniques` explicitly lists every approved technique.
6. `acknowledgement_env` names an environment variable containing exactly
   `I_ACKNOWLEDGE_ACTIVE_TESTING_IS_AUTHORIZED`.
7. Per-host requests, concurrency, and minimum delay remain within the hard
   bounds enforced by configuration validation.
8. Every scan target still matches `scope.allowed_targets`.

The acknowledgment belongs in the process environment, not YAML, source
control, shell history, or a report. It is a deliberate confirmation, not a
substitute for written authorization.

## Create and run an engagement template

Create a private copy:

```sh
make active-scan-template ACTIVE_CONFIG=configs/acme-active.yaml
```

Replace every `REPLACE_` value. Leave `active_testing.enabled: false` for a
normal bounded scan. To exercise the authorization gate, set a future expiry,
operator, acknowledgment variable name, and only the approved techniques:

```yaml
active_testing:
  enabled: true
  authorization_expires: "2026-09-08T17:00:00Z"
  operator: "analyst@example.com"
  acknowledgement_env: "ENUMSCAN_ACTIVE_ACK"
  allowed_techniques: ["tls_heartbleed", "web_sqli"]
  max_requests_per_host: 25
  max_concurrency: 1
  minimum_request_delay_ms: 500
```

Export the acknowledgment without putting it in the configuration:

```sh
export ENUMSCAN_ACTIVE_ACK=I_ACKNOWLEDGE_ACTIVE_TESTING_IS_AUTHORIZED
make active-scan CONFIG=configs/acme-active.yaml SCAN_ID=acme-active-001
```

Unset it when the authorized work is finished:

```sh
unset ENUMSCAN_ACTIVE_ACK
```

## Fail-closed behavior

Enumscan rejects expired or malformed timestamps, absent or incorrect
acknowledgments, empty allowlists, unknown or duplicate techniques, and safety
limits outside their permitted ranges. A failed gate occurs before network
modules start. Accepted active authorization is recorded as an
`audit_log_entry`, including its reference, expiry, operator, allowlist, and
limits, but never the acknowledgment value or credentials.

Idle and decoy scanning require every participating zombie or decoy system to
be separately and explicitly covered by the engagement. Their eventual runners
must not infer third-party authorization from authorization of the destination.

Credentialed runners must use environment or configured secret-manager
references. Credentials and retrieved secret values must never be stored as
assets, findings, events, logs, or report evidence.

