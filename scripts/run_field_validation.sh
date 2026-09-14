#!/usr/bin/env sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
result_dir=${1:-$repo_dir/dist/field-validation}
field_cache=${GOCACHE:-/tmp/enumscan-field-validation-cache}
mkdir -p "$result_dir"

case ${ENUMSCAN_BENCH_TARGETS:-1000} in
  *[!0-9]*|'') echo "ENUMSCAN_BENCH_TARGETS must be an integer" >&2; exit 2 ;;
esac

(
  cd "$repo_dir"
  {
    echo "enumscan synthetic field validation"
    echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "target_count=${ENUMSCAN_BENCH_TARGETS:-1000}"
    go version
    go env GOOS GOARCH
  } > "$result_dir/environment.txt"
  GOCACHE="$field_cache" go run ./cmd/enumscan capabilities -format json > "$result_dir/capabilities.json"
  ENUMSCAN_BENCH_TARGETS=${ENUMSCAN_BENCH_TARGETS:-1000} GOCACHE="$field_cache" \
    go test ./internal/engine -run '^$' -bench '^BenchmarkLargeScaleEventPipeline$' \
      -benchmem -benchtime=1x -count=1 > "$result_dir/pipeline-benchmark.txt"
  GOCACHE="$field_cache" go test -v ./internal/engine -run '^TestFieldValidation' > "$result_dir/operational-validation.txt"
  python3 scripts/evaluate_field_validation.py "$result_dir/pipeline-benchmark.txt" \
    "${ENUMSCAN_BENCH_TARGETS:-1000}" "$result_dir/threshold-summary.json"
)

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$result_dir"/* > "$result_dir/SHA256SUMS"
else
  shasum -a 256 "$result_dir"/* > "$result_dir/SHA256SUMS"
fi
echo "Field-validation artifacts written to $result_dir"
