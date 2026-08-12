GO ?= go
GOCACHE ?= /tmp/enumscan-go-build
GOFLAGS ?= -trimpath -buildvcs=true
CONFIG ?= configs/example.yaml
SCAN_ID ?=
FORMAT ?= markdown
OUTPUT_DIR ?= reports
BIN ?= dist/enumscan
NVD_FILE ?=
BASELINE_SCAN ?=
CURRENT_SCAN ?=

.DEFAULT_GOAL := help

.PHONY: help init-db serve dashboard run scan report analyze-vulnerabilities score-risk correlate compare-scans \
	build test test-compile vet fmt-check verify reproducible sbom vulncheck clean

help:
	@printf '%s\n' \
	  'enumscan development and operator targets:' \
	  '  make init-db CONFIG=configs/example.yaml' \
	  '  make dashboard CONFIG=configs/example.yaml' \
	  '  make scan CONFIG=configs/example.yaml SCAN_ID=authorized-scan' \
	  '  make report CONFIG=configs/example.yaml SCAN_ID=authorized-scan FORMAT=markdown' \
	  '  make analyze-vulnerabilities CONFIG=configs/example.yaml SCAN_ID=authorized-scan' \
	  '  make score-risk CONFIG=configs/example.yaml SCAN_ID=authorized-scan' \
	  '  make correlate CONFIG=configs/example.yaml SCAN_ID=authorized-scan' \
	  '  make compare-scans CONFIG=configs/example.yaml BASELINE_SCAN=scan-a CURRENT_SCAN=scan-b' \
	  '  make build | test | verify'

init-db:
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) init-db

# Starts the local operator dashboard at http://127.0.0.1:8080/.
serve dashboard:
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) server

# No target or scan ID is inferred: both must be present in the authorized config.
run scan:
	@test -n "$(SCAN_ID)" || (echo 'SCAN_ID is required, e.g. make scan SCAN_ID=authorized-scan'; exit 2)
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) run $(SCAN_ID)

report:
	@test -n "$(SCAN_ID)" || (echo 'SCAN_ID is required'; exit 2)
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) report $(SCAN_ID) -format $(FORMAT)

analyze-vulnerabilities:
	@test -n "$(SCAN_ID)" || (echo 'SCAN_ID is required'; exit 2)
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) analyze-vulnerabilities $(SCAN_ID)

score-risk:
	@test -n "$(SCAN_ID)" || (echo 'SCAN_ID is required'; exit 2)
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) score-risk $(SCAN_ID)

correlate:
	@test -n "$(SCAN_ID)" || (echo 'SCAN_ID is required'; exit 2)
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) correlate $(SCAN_ID)

compare-scans:
	@test -n "$(BASELINE_SCAN)" && test -n "$(CURRENT_SCAN)" || (echo 'BASELINE_SCAN and CURRENT_SCAN are required'; exit 2)
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) compare-scans $(BASELINE_SCAN) $(CURRENT_SCAN)

build:
	mkdir -p dist
	GOCACHE=$(GOCACHE) $(GO) build $(GOFLAGS) -o $(BIN) ./cmd/enumscan

test:
	GOCACHE=$(GOCACHE) $(GO) test ./...

# Fast compile-only check for restricted CI environments that prohibit local socket binds.
test-compile:
	GOCACHE=$(GOCACHE) $(GO) test ./... -run '^$$'

vet:
	GOCACHE=$(GOCACHE) $(GO) vet ./...

fmt-check:
	@test -z "$$($(GO)fmt -l $$(find . -name '*.go' -not -path './vendor/*'))" || (echo 'Run gofmt on the files above.'; exit 1)

verify: fmt-check vet test-compile

reproducible:
	mkdir -p dist/repro-a dist/repro-b
	GOCACHE=$(GOCACHE) $(GO) build $(GOFLAGS) -o dist/repro-a/enumscan ./cmd/enumscan
	GOCACHE=$(GOCACHE) $(GO) build $(GOFLAGS) -o dist/repro-b/enumscan ./cmd/enumscan
	cmp dist/repro-a/enumscan dist/repro-b/enumscan
	cp dist/repro-a/enumscan $(BIN)

# Produces a machine-readable dependency inventory. Use syft in release CI for CycloneDX.
sbom:
	mkdir -p dist
	$(GO) list -m -json all > dist/dependencies.json

vulncheck:
	GOCACHE=$(GOCACHE) $(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

clean:
	rm -rf dist
