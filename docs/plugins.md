# Plugins and marketplace

Plugins are never auto-loaded by scans. Discovery, installation, activation,
and execution are separate explicit operations.

## Marketplace trust

Registry queries require an explicitly configured HTTPS endpoint; loopback HTTP
is permitted for development. Installation requires a pinned Ed25519 public key
from an environment variable. Packages are size-bounded, redirect-resistant,
checksum-verified, signature-verified, manifest-validated, and installed into a
versioned directory. Community plugins follow the same verification policy.

## Commands

```sh
enumscan plugin-search -registry https://registry.example -query headers
enumscan plugin-install -registry https://registry.example -id plugin-id \
  -dir /opt/enumscan/plugins -trusted-key-env ENUMSCAN_PLUGIN_PUBLIC_KEY
enumscan plugin-update -registry https://registry.example -id plugin-id \
  -dir /opt/enumscan/plugins -trusted-key-env ENUMSCAN_PLUGIN_PUBLIC_KEY
```

`plugin-rate` submits a 1–5 rating. `plugin-registry` starts the registry server
from a publication catalog and environment-held signing key; non-loopback
listeners require TLS.

## Runtimes

Lua runs in an embedded interpreter with cancellation, output limits, and a
restricted standard library. OS, process, and unrestricted file libraries are
absent. Network use requires a manifest permission and remains target-scoped.

gRPC plugins implement `/enumscan.plugin.v1.Plugin/Execute` using protobuf
`Struct` messages. Remote endpoints require TLS; plaintext is loopback-only.
Declared write permissions are enforced for both runtimes.

These controls are application-level isolation, not a general-purpose OS
sandbox. Review plugin code and permissions before trusting its signing key.

See [plugin_sdk.html](plugin_sdk.html) and the examples under `plugins/`.

