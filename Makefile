GO ?= go
GOCACHE ?= /tmp/enumscan-go-build
GOFLAGS ?= -trimpath -buildvcs=true
CONFIG ?= configs/example.yaml
ACTIVE_CONFIG ?= configs/my-active-scan.yaml
TEMPLATE ?=
OUTPUT_CONFIG ?= configs/my-scan.yaml
SCAN_ID ?=
FORMAT ?= markdown
OUTPUT_DIR ?= reports
BIN ?= dist/enumscan
NVD_FILE ?=
BASELINE_SCAN ?=
CURRENT_SCAN ?=
BACKUP_PATH ?=
BACKUP_KEY_ENV ?= ENUMSCAN_BACKUP_KEY

.DEFAULT_GOAL := help

.PHONY: help init-db backup-encrypted postgres-migrate serve dashboard run scan monitor distributed-status distributed-agent interactive-scan scan-template scan-templates new-scan-config active-scan-template active-scan docs doctor doctor-remote report notify-webhook notify-slack notify-email local-llm-summary sync-neo4j analyze-vulnerabilities score-risk correlate compare-scans \
	build build-cross checksums image test test-compile vet fmt-check verify reproducible sbom vulncheck threat-intel-test git-secrets tui clean

help:
	@printf '%s\n' \
	  'enumscan development and operator targets:' \
	  '  make init-db CONFIG=configs/example.yaml' \
	  '  make backup-encrypted CONFIG=configs/my-scan.yaml BACKUP_PATH=/secure/path/enumscan.esb  # requires an AES-256 key in ENUMSCAN_BACKUP_KEY' \
	  '  make postgres-migrate CONFIG=configs/postgres.template.yaml  # explicit PostgreSQL core-schema preflight' \
	  '  make dashboard CONFIG=configs/example.yaml' \
	  '  make scan CONFIG=configs/example.yaml SCAN_ID=authorized-scan' \
	  '  make monitor CONFIG=configs/monitor.template.yaml  # bounded recurring authorized scans' \
	  '  make distributed-status CONFIG=configs/example.yaml  # local coordinator ledger only; does not dispatch work' \
	  '  make distributed-agent CONFIG=configs/agent.yaml AGENT_ID=agent-east COORDINATOR_URL=https://coordinator:8080' \
	  '  make interactive-scan   # prompts for authorized IP/CIDR, profile, and authorization reference' \
	  '  make scan-template      # copies configs/scan.template.yaml to configs/my-scan.yaml' \
	  '  make scan-templates     # list assessment-specific templates' \
	  '  make new-scan-config TEMPLATE=web OUTPUT_CONFIG=configs/acme.yaml' \
	  '  make active-scan-template ACTIVE_CONFIG=configs/my-active-scan.yaml' \
	  '  make active-scan CONFIG=configs/my-active-scan.yaml SCAN_ID=authorized-active-scan' \
	  '  make docs               # regenerate HTML documentation from Markdown' \
	  '  make doctor CONFIG=configs/my-scan.yaml  # offline provider preflight; no network requests' \
	  '  make doctor-remote CONFIG=configs/my-scan.yaml  # explicitly probes configured providers; may consume quota' \
	  '  make report CONFIG=configs/example.yaml SCAN_ID=authorized-scan FORMAT=markdown' \
	  '  make notify-webhook CONFIG=configs/my-scan.yaml SCAN_ID=authorized-scan WEBHOOK_URL=https://...' \
	  '  make notify-slack CONFIG=configs/my-scan.yaml SCAN_ID=authorized-scan SLACK_WEBHOOK_URL=https://...' \
	  '  make notify-email CONFIG=configs/my-scan.yaml SCAN_ID=authorized-scan SMTP_SERVER=smtp.example:587 EMAIL_FROM=... EMAIL_TO=...' \
	  '  make local-llm-summary CONFIG=configs/my-scan.yaml SCAN_ID=authorized-scan  # configured loopback Ollama only' \
	  '  make sync-neo4j CONFIG=configs/my-scan.yaml SCAN_ID=authorized-scan  # explicit configured evidence sync' \
	  '  make analyze-vulnerabilities CONFIG=configs/example.yaml SCAN_ID=authorized-scan' \
	  '  make score-risk CONFIG=configs/example.yaml SCAN_ID=authorized-scan' \
	  '  make correlate CONFIG=configs/example.yaml SCAN_ID=authorized-scan' \
	  '  make compare-scans CONFIG=configs/example.yaml BASELINE_SCAN=scan-a CURRENT_SCAN=scan-b' \
	  '  make git-secrets CONFIG=configs/example.yaml SCAN_ID=repo-a REPO=/absolute/path/to/repo' \
	  '  make tui CONFIG=configs/example.yaml' \
	  '  make build | test | verify'

init-db:
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) init-db

backup-encrypted:
	@test -n "$(BACKUP_PATH)" || (echo 'BACKUP_PATH is required'; exit 2)
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) backup-encrypted "$(BACKUP_PATH)" -key-env "$(BACKUP_KEY_ENV)"

postgres-migrate:
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) postgres-migrate

# Starts the local operator dashboard at http://127.0.0.1:8080/.
serve dashboard:
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) server

# No target or scan ID is inferred: both must be present in the authorized config.
run scan:
	@test -n "$(SCAN_ID)" || (echo 'SCAN_ID is required, e.g. make scan SCAN_ID=authorized-scan'; exit 2)
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) run $(SCAN_ID)

monitor:
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) monitor

distributed-status:
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) distributed-status

distributed-agent:
	@test -n "$(AGENT_ID)" && test -n "$(COORDINATOR_URL)" || (echo 'AGENT_ID and COORDINATOR_URL are required'; exit 2)
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) distributed-agent -agent "$(AGENT_ID)" -coordinator "$(COORDINATOR_URL)"

# Creates an editable, engagement-specific copy without overwriting an existing file.
scan-template:
	@test ! -e configs/my-scan.yaml || (echo 'configs/my-scan.yaml already exists; choose another filename or edit it directly'; exit 2)
	cp configs/scan.template.yaml configs/my-scan.yaml
	@echo 'Created configs/my-scan.yaml. Replace the REPLACE_ values before running make scan CONFIG=configs/my-scan.yaml SCAN_ID=<id>.'

scan-templates:
	@printf '%s\n' external internal web api active-directory kubernetes cloud bug-bounty compliance passive active-testing

new-scan-config:
	@test -n "$(TEMPLATE)" || (echo 'TEMPLATE is required; run make scan-templates'; exit 2)
	sh scripts/new_scan_config.sh "$(TEMPLATE)" "$(OUTPUT_CONFIG)"

# Creates a private Tier 4 engagement config without overwriting an existing file.
active-scan-template:
	@test ! -e "$(ACTIVE_CONFIG)" || (echo '$(ACTIVE_CONFIG) already exists; choose another ACTIVE_CONFIG'; exit 2)
	cp configs/active-testing.template.yaml "$(ACTIVE_CONFIG)"
	@echo 'Created $(ACTIVE_CONFIG). Read docs/tier4_active_testing.md and replace every REPLACE_ value.'

# Configuration validation performs the active authorization preflight before
# the engine starts. Individual probe runners may only execute allowlisted names.
active-scan: scan

docs:
	sh scripts/build_docs.sh

# Reports only local passive-intelligence configuration and environment-variable
# presence. It never contacts providers or displays credential values.
doctor:
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) doctor

# An explicit, bounded provider probe. This sends a non-target example.invalid
# query only to configured credentialed providers and may consume API quota.
doctor-remote:
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) doctor -remote

# Guided one-off workflow. It writes a 0600 temporary config, runs only against
# the entered scope, and removes that temporary config at the end.
interactive-scan:
	@set -eu; \
	printf 'Authorized IP or CIDR: ' >&2; read -r target; \
	case "$$target" in ''|*[!0-9A-Fa-f:./]*) echo 'Target must be an IPv4/IPv6 address or CIDR.' >&2; exit 2;; esac; \
	printf 'Scan type [quick|standard|exhaustive] (standard): ' >&2; read -r profile; \
	profile=$${profile:-standard}; \
	case "$$profile" in quick|standard|exhaustive) ;; *) echo 'Scan type must be quick, standard, or exhaustive.' >&2; exit 2;; esac; \
	printf 'Written authorization reference: ' >&2; read -r authorization; \
	case "$$authorization" in ''|*[![:alnum:]_.:/-]*) echo 'Authorization reference may contain only letters, numbers, ., _, :, /, and -.' >&2; exit 2;; esac; \
	scan_id=interactive-$$(date +%Y%m%d%H%M%S); \
	tmp_config=$$(mktemp "$${TMPDIR:-/tmp}/enumscan-scan.XXXXXX"); \
	trap 'rm -f "$$tmp_config"' EXIT HUP INT TERM; \
	umask 077; \
	printf '%s\n' \
	  'database:' '  path: "data/enumscan-interactive.sqlite"' \
	  'scope:' "  allowed_targets: [\"$$target\"]" "  authorization: \"$$authorization\"" \
	  'scheduler:' '  concurrency: 4' '  global_rate_limit_ms: 100' '  per_target_rate_limit_ms: 250' '  module_timeout_ms: 15000' \
	  'discovery:' '  cidr_max_hosts: 256' '  enable_dns_discovery: true' '  enable_dns_records: true' '  enable_reverse_dns: true' '  enable_wildcard_dns: true' '  enable_rdap: false' '  enable_icmp_sweep: false' '  enable_tcp_host_probes: true' '  tcp_probe_ports: [22, 80, 443]' '  enable_udp_live_probes: false' '  udp_probe_ports: []' '  passive_dns_files: []' '  certificate_transparency_files: []' '  passive_capture_files: []' \
	  'portscan:' "  profile: \"$$profile\"" '  tcp_ports: []' '  udp_ports: []' '  enable_tcp: true' '  enable_udp: false' '  enable_banner: true' '  enable_raw_syn: false' '  enable_raw_scanning: false' '  max_concurrent_ports: 8' '  record_closed_ports: false' '  base_timeout_ms: 750' '  max_timeout_ms: 3000' \
	  'http:' '  max_depth: 1' '  max_pages_per_host: 25' '  enable_tls: true' '  enable_crawler: true' '  enable_js_analysis: true' '  enable_api_discovery: true' '  enable_screenshots: false' '  enable_directory_api: true' '  enable_secret_intelligence: true' '  enable_web_manifest: true' '  enable_redirect_tracking: true' '  enable_method_enumeration: true' '  enable_source_map_analysis: true' '  max_directory_paths: 80' '  directory_wordlist: []' '  api_paths: []' \
	  'specialized:' '  enable_protocol_enumeration: true' '  enable_smb: false' '  enable_ldap: false' '  enable_snmp: false' '  enable_cloud: false' '  enable_container: false' '  enable_database: false' '  snmp_communities: []' \
	  'passive_intel:' '  enabled: false' '  sources: []' \
	  'scan:' "  profile: \"$$profile\"" "  targets: [\"$$target\"]" '  ports: []' \
	  'reporting:' '  output_dir: "reports"' > "$$tmp_config"; \
	echo "Starting $$profile scan $$scan_id for $$target"; \
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config "$$tmp_config" run "$$scan_id"

report:
	@test -n "$(SCAN_ID)" || (echo 'SCAN_ID is required'; exit 2)
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) report $(SCAN_ID) -format $(FORMAT)

# Explicit delivery only. HTTPS is required by enumscan except for localhost
# test endpoints; delivery never happens automatically during a scan.
notify-webhook:
	@test -n "$(SCAN_ID)" && test -n "$(WEBHOOK_URL)" || (echo 'SCAN_ID and WEBHOOK_URL are required'; exit 2)
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) notify-webhook $(SCAN_ID) -url "$(WEBHOOK_URL)"

notify-slack:
	@test -n "$(SCAN_ID)" && test -n "$(SLACK_WEBHOOK_URL)" || (echo 'SCAN_ID and SLACK_WEBHOOK_URL are required'; exit 2)
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) notify-slack $(SCAN_ID) -url "$(SLACK_WEBHOOK_URL)"

notify-email:
	@test -n "$(SCAN_ID)" && test -n "$(SMTP_SERVER)" && test -n "$(EMAIL_FROM)" && test -n "$(EMAIL_TO)" || (echo 'SCAN_ID, SMTP_SERVER, EMAIL_FROM, and EMAIL_TO are required'; exit 2)
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) notify-email $(SCAN_ID) -server "$(SMTP_SERVER)" -from "$(EMAIL_FROM)" -to "$(EMAIL_TO)" $(if $(SMTP_USERNAME),-username "$(SMTP_USERNAME)")

local-llm-summary:
	@test -n "$(SCAN_ID)" || (echo 'SCAN_ID is required'; exit 2)
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) local-llm-summary $(SCAN_ID)

sync-neo4j:
	@test -n "$(SCAN_ID)" || (echo 'SCAN_ID is required'; exit 2)
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) sync-neo4j $(SCAN_ID)

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

# Inspects only an explicitly named local worktree. The command never contacts
# a remote and stores redacted fingerprints instead of raw credential values.
git-secrets:
	@test -n "$(SCAN_ID)" && test -n "$(REPO)" || (echo 'SCAN_ID and REPO are required'; exit 2)
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) git-secrets $(SCAN_ID) -repo "$(REPO)"

tui:
	GOCACHE=$(GOCACHE) $(GO) run ./cmd/enumscan -config $(CONFIG) tui

build:
	mkdir -p dist
	GOCACHE=$(GOCACHE) $(GO) build $(GOFLAGS) -o $(BIN) ./cmd/enumscan

# Cross-compilation is pure Go and produces operator binaries without running
# them. This is also the artifact set used by the release workflow.
build-cross:
	mkdir -p dist
	GOCACHE=$(GOCACHE) GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o dist/enumscan-linux-amd64 ./cmd/enumscan
	GOCACHE=$(GOCACHE) GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o dist/enumscan-darwin-arm64 ./cmd/enumscan
	GOCACHE=$(GOCACHE) GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o dist/enumscan-windows-amd64.exe ./cmd/enumscan

# Release CI invokes this only after reproducible and cross-platform builds.
# The manifest is signed with the accompanying binaries, so operators can
# verify their downloaded artifact before execution.
checksums:
	sha256sum dist/enumscan dist/enumscan-linux-amd64 dist/enumscan-darwin-arm64 dist/enumscan-windows-amd64.exe > dist/enumscan-sha256sums.txt

# Build only: image publication is intentionally a separate, release-approved
# action outside this Make target.
image:
	docker build --pull --tag enumscan:local .

test:
	GOCACHE=$(GOCACHE) $(GO) test ./...

# Fast compile-only check for restricted CI environments that prohibit local socket binds.
test-compile:
	GOCACHE=$(GOCACHE) $(GO) test ./... -run '^$$'

vet:
	GOCACHE=$(GOCACHE) $(GO) vet ./...

fmt-check:
	@test -z "$$($(GO)fmt -l $$(find . -name '*.go' -not -path './vendor/*'))" || (echo 'Run gofmt on the files above.'; exit 1)

verify: fmt-check vet test

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
	GOCACHE=$(GOCACHE) $(GO) run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...

threat-intel-test:
	python3 -m unittest scripts/test_sync_threat_intel.py

clean:
	rm -rf dist
