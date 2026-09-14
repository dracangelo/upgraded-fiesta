#!/usr/bin/env bash
# Create versioned operator archives from already-built cross-platform binaries.
# This script does not build, sign, publish, or infer a release version.
set -euo pipefail

release_version=${1:?usage: scripts/package_release.sh <version> [dist-directory]}
release_dist=${2:-dist}
release_dist=$(cd "$release_dist" && pwd)

command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 2; }
command -v zip >/dev/null 2>&1 || { echo "zip is required" >&2; exit 2; }

case "$release_version" in
  v[0-9]*|[0-9]*) ;;
  *) echo "release version must begin with v or a digit" >&2; exit 2 ;;
esac

for artifact in enumscan-linux-amd64 enumscan-darwin-arm64 enumscan-windows-amd64.exe; do
  if [ ! -f "$release_dist/$artifact" ]; then
    echo "missing release binary: $release_dist/$artifact" >&2
    exit 2
  fi
done

release_stage=$(mktemp -d)
trap 'rm -rf "$release_stage"' EXIT HUP INT TERM

make_archive() {
  archive_platform=$1
  source_binary=$2
  archive_kind=$3
  archive_root="enumscan-${release_version}-${archive_platform}"
  archive_dir="$release_stage/$archive_root"
  mkdir -p "$archive_dir"
  case "$source_binary" in
    *.exe) archive_binary=enumscan.exe ;;
    *) archive_binary=enumscan ;;
  esac
  cp "$release_dist/$source_binary" "$archive_dir/$archive_binary"
  cp README.md "$archive_dir/README.md"
  cp docs/authorized_use.md "$archive_dir/AUTHORIZED_USE.md"
  cp configs/scan.template.yaml "$archive_dir/scan.template.yaml"
	# ZIP stores source timestamps, so normalize staging metadata for reproducible
	# archives. 1980-01-01 is the earliest portable ZIP timestamp.
  find "$archive_dir" -exec touch -h -d '@315532800' {} +
  if [ "$archive_kind" = tar ]; then
    tar -C "$release_stage" --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -czf "$release_dist/${archive_root}.tar.gz" "$archive_root"
  else
    (cd "$release_stage" && TZ=UTC zip -X -q -r "$release_dist/${archive_root}.zip" "$archive_root")
  fi
}

make_archive linux-amd64 enumscan-linux-amd64 tar
make_archive darwin-arm64 enumscan-darwin-arm64 tar
make_archive windows-amd64 enumscan-windows-amd64.exe zip
