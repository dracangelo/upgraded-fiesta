#!/usr/bin/env sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
docs_dir="$repo_dir/docs"
template="$docs_dir/template.html"

command -v pandoc >/dev/null 2>&1 || {
  echo "pandoc is required to build HTML documentation" >&2
  exit 1
}

build_page() {
  source_file=$1
  output_file=$2
	page_title=$(sed -n 's/^# //p' "$docs_dir/$source_file" | head -n 1)
  pandoc --from=gfm --to=html5 --standalone --template="$template" \
		--metadata="title=$page_title" \
    --output="$docs_dir/$output_file" "$docs_dir/$source_file"
  sed -i 's/\.md\([#"]\)/.html\1/g' "$docs_dir/$output_file"
}

build_page README.md index.html
build_page getting-started.md getting-started.html
build_page configuration.md configuration.html
build_page cli.md cli.html
build_page architecture.md architecture-guide.html
build_page scanning.md scanning.html
build_page reporting-api.md reporting-api.html
build_page operations.md operations.html
build_page security.md security.html
build_page plugins.md plugins.html
build_page development.md development.html
build_page tier4_active_testing.md tier4_active_testing.html

# Legacy URLs remain stable, but their content now comes from the maintained
# Markdown guides rather than independent, drifting HTML.
build_page architecture.md architecture.html
build_page development.md module_developer_guide.html
build_page plugins.md plugin_sdk.html
build_page reporting-api.md api_reference.html
build_page getting-started.md operator_guide.html
build_page configuration.md configuration_reference.html
build_page security.md authorized_use.html
build_page security.md threat_model.html
build_page operations.md performance_tuning.html

echo "Built Enumscan HTML documentation in $docs_dir"
