#!/usr/bin/env bash
# Produce package-manager artifacts from an already-built, release-verified
# Linux/Windows/macOS artifact set. This script never downloads, publishes, or
# signs anything; release CI signs every file it creates.
set -euo pipefail

release_version=${1:?usage: scripts/package_system_packages.sh <version> [dist-directory]}
release_dist=${2:-dist}
release_dist=$(cd "$release_dist" && pwd)
repository=${ENUMSCAN_RELEASE_REPOSITORY:-dracangelo/upgraded-fiesta}

case "$release_version" in
  v[0-9]*|[0-9]*) ;;
  *) echo "release version must begin with v or a digit" >&2; exit 2 ;;
esac
case "$repository" in
  *" "*|*..*|/*|*\\*) echo "ENUMSCAN_RELEASE_REPOSITORY must be an owner/repository value" >&2; exit 2 ;;
esac

for command in dpkg-deb rpmbuild sha256sum; do
  command -v "$command" >/dev/null 2>&1 || { echo "$command is required" >&2; exit 2; }
done

linux_binary="$release_dist/enumscan-linux-amd64"
mac_archive="enumscan-${release_version}-darwin-arm64.tar.gz"
windows_archive="enumscan-${release_version}-windows-amd64.zip"
for artifact in "$linux_binary" "$release_dist/$mac_archive" "$release_dist/$windows_archive"; do
  [ -f "$artifact" ] || { echo "missing release artifact: $artifact" >&2; exit 2; }
done

release_tag=$release_version
case "$release_tag" in v*) ;; *) release_tag="v$release_tag" ;; esac
package_version=${release_version#v}
debian_version=${package_version//-/~}
rpm_version=${package_version//-/~}
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM

install -D -m 0755 "$linux_binary" "$stage/deb/usr/bin/enumscan"
install -D -m 0644 README.md "$stage/deb/usr/share/doc/enumscan/README.md"
install -D -m 0644 docs/authorized_use.md "$stage/deb/usr/share/doc/enumscan/AUTHORIZED_USE.md"
install -D -m 0644 configs/scan.template.yaml "$stage/deb/usr/share/doc/enumscan/scan.template.yaml"
mkdir -p "$stage/deb/DEBIAN"
cat > "$stage/deb/DEBIAN/control" <<EOF
Package: enumscan
Version: ${debian_version}
Section: admin
Priority: optional
Architecture: amd64
Maintainer: Enumscan maintainers
Description: Authorized security-assessment enumeration platform
 Enumscan discovers and records authorized assessment evidence. It does not
 perform exploitation and enforces configured scope boundaries.
EOF
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0} dpkg-deb --root-owner-group --build "$stage/deb" "$release_dist/enumscan_${debian_version}_amd64.deb" >/dev/null

rpm_root="$stage/rpm"
mkdir -p "$rpm_root"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
cp "$linux_binary" "$rpm_root/SOURCES/enumscan"
cp README.md "$rpm_root/SOURCES/README.md"
cp docs/authorized_use.md "$rpm_root/SOURCES/AUTHORIZED_USE.md"
cp configs/scan.template.yaml "$rpm_root/SOURCES/scan.template.yaml"
cat > "$rpm_root/SPECS/enumscan.spec" <<EOF
Name:           enumscan
Version:        ${rpm_version}
Release:        1%{?dist}
Summary:        Authorized security-assessment enumeration platform
License:        NOASSERTION
URL:            https://github.com/${repository}
BuildArch:      x86_64
Source0:        enumscan
Source1:        README.md
Source2:        AUTHORIZED_USE.md
Source3:        scan.template.yaml

%description
Enumscan discovers and records authorized assessment evidence. It does not
perform exploitation and enforces configured scope boundaries.

%install
install -Dpm0755 %{SOURCE0} %{buildroot}%{_bindir}/enumscan
install -Dpm0644 %{SOURCE1} %{buildroot}%{_defaultdocdir}/enumscan/README.md
install -Dpm0644 %{SOURCE2} %{buildroot}%{_defaultdocdir}/enumscan/AUTHORIZED_USE.md
install -Dpm0644 %{SOURCE3} %{buildroot}%{_defaultdocdir}/enumscan/scan.template.yaml

%files
%{_bindir}/enumscan
%doc %{_defaultdocdir}/enumscan/README.md
%doc %{_defaultdocdir}/enumscan/AUTHORIZED_USE.md
%doc %{_defaultdocdir}/enumscan/scan.template.yaml
EOF
SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0} rpmbuild --define "_topdir $rpm_root" --define "_buildhost reproducible" --define "_dbpath $rpm_root/rpmdb" -bb "$rpm_root/SPECS/enumscan.spec" >/dev/null
rpm_file=$(find "$rpm_root/RPMS" -type f -name 'enumscan-*.x86_64.rpm' -print -quit)
[ -n "$rpm_file" ] || { echo "rpmbuild did not produce an x86_64 RPM" >&2; exit 1; }
cp "$rpm_file" "$release_dist/enumscan-${package_version}-1.x86_64.rpm"

mac_hash=$(sha256sum "$release_dist/$mac_archive" | awk '{print $1}')
windows_hash=$(sha256sum "$release_dist/$windows_archive" | awk '{print $1}')
release_url="https://github.com/${repository}/releases/download/${release_tag}"
cat > "$release_dist/enumscan-${package_version}-homebrew.rb" <<EOF
class Enumscan < Formula
  desc "Scope-locked reconnaissance for authorized security assessments"
  homepage "https://github.com/${repository}"
  on_arm do
    url "${release_url}/${mac_archive}"
    sha256 "${mac_hash}"
  end
  version "${package_version}"

  def install
    bin.install "enumscan-${release_version}-darwin-arm64/enumscan"
    doc.install "enumscan-${release_version}-darwin-arm64/README.md"
    doc.install "enumscan-${release_version}-darwin-arm64/AUTHORIZED_USE.md"
    pkgshare.install "enumscan-${release_version}-darwin-arm64/scan.template.yaml"
  end

  test do
    system "#{bin}/enumscan", "help"
  end
end
EOF
cat > "$release_dist/enumscan-${package_version}-scoop.json" <<EOF
{
  "version": "${package_version}",
  "description": "Scope-locked reconnaissance for authorized security assessments",
  "homepage": "https://github.com/${repository}",
  "architecture": {
    "64bit": {
      "url": "${release_url}/${windows_archive}",
      "hash": "${windows_hash}",
      "extract_dir": "enumscan-${release_version}-windows-amd64"
    }
  },
  "bin": "enumscan.exe",
  "checkver": "github"
}
EOF

echo "System-package artifacts written to $release_dist"
