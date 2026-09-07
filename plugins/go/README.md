# Go Plugin Direction

Enumscan provides an embedded, restricted Lua runtime and a protobuf-backed
gRPC client runtime. Installed marketplace packages are never activated merely
because they exist on disk; callers must verify and explicitly load them.

Go shared-object plugins remain unsupported because they do not provide the
process boundary used by the gRPC runtime.

Recommended contract:

```text
Plugin subscribes to event types
Plugin receives scan id, target, and event metadata
Plugin returns new assets, findings, and events
Core enforces scope before dispatch and before accepting new targets
```
