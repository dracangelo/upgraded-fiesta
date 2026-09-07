#!/usr/bin/env sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
template_name=${1:-}
output_path=${2:-}

if [ -z "$template_name" ] || [ -z "$output_path" ]; then
  echo "usage: $0 <template-name> <output-path>" >&2
  exit 2
fi

case "$template_name" in
  external|internal|web|api|active-directory|kubernetes|cloud|bug-bounty|compliance|passive|active-testing)
    ;;
  *)
    echo "unknown template: $template_name" >&2
    echo "available: external internal web api active-directory kubernetes cloud bug-bounty compliance passive active-testing" >&2
    exit 2
    ;;
esac

case "$template_name" in
  external) source_name=external-infrastructure.yaml ;;
  internal) source_name=internal-network.yaml ;;
  web) source_name=web-application.yaml ;;
  api) source_name=api-assessment.yaml ;;
  cloud) source_name=cloud-infrastructure.yaml ;;
  passive) source_name=passive-intelligence.yaml ;;
  active-testing) source_name=../active-testing.template.yaml ;;
  *) source_name=$template_name.yaml ;;
esac

source_path="$repo_dir/configs/templates/$source_name"
if [ -e "$output_path" ]; then
  echo "$output_path already exists; refusing to overwrite it" >&2
  exit 2
fi

cp "$source_path" "$output_path"
chmod 600 "$output_path"
echo "Created $output_path from the $template_name template. Replace every REPLACE_ value before use."
