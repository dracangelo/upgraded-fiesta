# Development guide

## Local checks

```sh
make fmt-check
make vet
make test
make verify
```

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

## Building the HTML manual

Markdown under `docs/` is canonical. Install Pandoc, then run:

```sh
make docs
```

This regenerates the styled HTML manual, including the stable legacy HTML
filenames. Do not hand-edit generated HTML; update its Markdown source, shared
template, or stylesheet instead.
