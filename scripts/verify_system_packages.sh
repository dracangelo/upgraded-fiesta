#!/usr/bin/env bash
# Check package contents and generated package-manager definitions without
# installing anything on the operator workstation.
set -euo pipefail

release_dist=${1:-dist}
release_dist=$(cd "$release_dist" && pwd)
command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb is required" >&2; exit 2; }
command -v rpm >/dev/null 2>&1 || { echo "rpm is required" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "python3 is required" >&2; exit 2; }

deb_package=$(find "$release_dist" -maxdepth 1 -type f -name 'enumscan_*.deb' -print -quit)
rpm_package=$(find "$release_dist" -maxdepth 1 -type f -name 'enumscan-*.x86_64.rpm' -print -quit)
formula=$(find "$release_dist" -maxdepth 1 -type f -name 'enumscan-*-homebrew.rb' -print -quit)
scoop_manifest=$(find "$release_dist" -maxdepth 1 -type f -name 'enumscan-*-scoop.json' -print -quit)
for artifact in "$deb_package" "$rpm_package" "$formula" "$scoop_manifest"; do
  [ -n "$artifact" ] || { echo "required system-package artifact is missing" >&2; exit 1; }
done

dpkg-deb --info "$deb_package" >/dev/null
deb_contents=$(dpkg-deb --contents "$deb_package")
echo "$deb_contents" | grep -q 'usr/bin/enumscan$'
rpm_contents=$(rpm --define "_dbpath /tmp" -qpl "$rpm_package")
echo "$rpm_contents" | grep -q '^/usr/bin/enumscan$'
grep -q '^class Enumscan < Formula$' "$formula"
grep -q 'sha256 "[0-9a-f]\{64\}"' "$formula"
python3 - "$scoop_manifest" <<'PY'
import json
import pathlib
import re
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
arch = manifest.get("architecture", {}).get("64bit", {})
if manifest.get("bin") != "enumscan.exe" or not re.fullmatch(r"[0-9a-f]{64}", arch.get("hash", "")):
    raise SystemExit("invalid Scoop manifest")
PY
echo "System-package validation passed"
