# Development guide

## Local checks

```sh
make fmt-check
make vet
make test
make verify
```

The dashboard is bundled from the JSX source with pinned npm dependencies:

```sh
npm --prefix _frontend ci --ignore-scripts
make dashboard-check
```

The generated embedded dashboard must be committed so Go builds require no
Node.js toolchain and the application needs no runtime CDN access.

`make test-compile` is available in restricted environments that cannot bind
loopback fixture sockets. It is not a substitute for the complete test suite.

## Repository layout

- Commands live in `cmd/enumscan`.
- Domain models live in `internal/models`.
- Configuration defaults, parsing, validation, and profiles live in
  `internal/config`.
- Runtime modules live in `internal/modules` and communicate through events.
- Persistence changes require migrations and store tests.
- User-visible behavior requires documentation and a runnable fixture or test.

## Adding a module

1. Define precise event subscriptions and outputs.
2. Validate scope immediately before every network action.
3. Bound concurrency, response sizes, retries, and timeouts.
4. Preserve observed versus heuristic confidence.
5. Redact credentials and sensitive response content.
6. Add focused local-server fixtures and pipeline coverage.
7. Register the module only through an appropriate profile/configuration gate.

## Quality expectations

Tests should be deterministic and must not depend on public services. Use local
fixtures for protocols and injected HTTP transports for provider APIs. Run
`git diff --check` and the full Go suite before handing off changes.

Release-sensitive dependency changes should also run `make vulncheck` and
reproducibility checks. See [module_developer_guide.html](module_developer_guide.html)
for the detailed module interface.

Run `make field-validation` for a network-free pipeline artifact containing
environment metadata, the capability manifest, benchmark/allocation results,
and checksums. Set `ENUMSCAN_BENCH_TARGETS` from 1 to 100000 to choose the
synthetic engagement size. CI exercises 100, 1,000, and 10,000 targets on
Linux, macOS, and Windows. Authorized live-environment results must be recorded
separately and must not contain customer target data.

## Building the HTML manual

Markdown under `docs/` is canonical. Install Pandoc, then run:

```sh
make docs
```

This regenerates the styled HTML manual, including the stable legacy HTML
filenames. Do not hand-edit generated HTML; update its Markdown source, shared
template, or stylesheet instead.
