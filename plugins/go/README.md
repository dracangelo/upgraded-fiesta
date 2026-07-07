# Go Plugin Direction

The current scaffold uses in-process Go modules behind the scheduler `Module` interface.

Future external plugin options:

- Go shared-object plugins for same-host trusted modules.
- gRPC plugins for language-neutral and sandboxable extensions.
- Lua plugins for lightweight service fingerprints and HTTP checks.

Recommended contract:

```text
Plugin subscribes to event types
Plugin receives scan id, target, and event metadata
Plugin returns new assets, findings, and events
Core enforces scope before dispatch and before accepting new targets
```

