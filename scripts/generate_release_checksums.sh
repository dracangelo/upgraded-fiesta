#!/usr/bin/env bash
# Generate a portable checksum file whose paths are relative to a release
# download directory rather than the CI workspace.
set -euo pipefail

checksum_dist=${1:-dist}
cd "$checksum_dist"

artifacts=(enumscan enumscan-linux-amd64 enumscan-darwin-arm64 enumscan-windows-amd64.exe)
for archive in enumscan-*.tar.gz enumscan-*.zip; do
  [ -e "$archive" ] || continue
  artifacts+=("$archive")
done
for package in enumscan_*.deb enumscan-*.rpm enumscan-*-homebrew.rb enumscan-*-scoop.json; do
  [ -e "$package" ] || continue
  artifacts+=("$package")
done

sha256sum "${artifacts[@]}" | LC_ALL=C sort > enumscan-sha256sums.txt
