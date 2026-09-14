class Enumscan < Formula
  desc "Scope-locked reconnaissance for authorized security assessments"
  homepage "https://github.com/dracangelo/upgraded-fiesta"
  on_arm do
    url "https://github.com/dracangelo/upgraded-fiesta/releases/download/v0.9.0/enumscan-v0.9.0-darwin-arm64.tar.gz"
    sha256 "b931bd85631d8dbff637fd6fc866e97ddc7968949be713fa38c870439d0a1bf3"
  end
  version "0.9.0"

  def install
    bin.install "enumscan-v0.9.0-darwin-arm64/enumscan"
    doc.install "enumscan-v0.9.0-darwin-arm64/README.md"
    doc.install "enumscan-v0.9.0-darwin-arm64/AUTHORIZED_USE.md"
    pkgshare.install "enumscan-v0.9.0-darwin-arm64/scan.template.yaml"
  end

  test do
    system "#{bin}/enumscan", "help"
  end
end
