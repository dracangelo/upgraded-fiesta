GOFLAGS ?= -trimpath -buildvcs=true
GOCACHE ?= /tmp/enumscan-go-build

.PHONY: test vet build verify reproducible sbom vulncheck

test:
	GOCACHE=$(GOCACHE) go test ./...

vet:
	GOCACHE=$(GOCACHE) go vet ./...

build:
	mkdir -p dist
	GOCACHE=$(GOCACHE) go build $(GOFLAGS) -o dist/enumscan ./cmd/enumscan

verify: vet test reproducible

reproducible:
	mkdir -p dist/repro-a dist/repro-b
	GOCACHE=$(GOCACHE) go build $(GOFLAGS) -o dist/repro-a/enumscan ./cmd/enumscan
	GOCACHE=$(GOCACHE) go build $(GOFLAGS) -o dist/repro-b/enumscan ./cmd/enumscan
	cmp dist/repro-a/enumscan dist/repro-b/enumscan
	cp dist/repro-a/enumscan dist/enumscan

# Produces a machine-readable dependency inventory. Use syft in the release
# workflow for a CycloneDX SBOM artifact.
sbom:
	mkdir -p dist
	go list -m -json all > dist/dependencies.json

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
