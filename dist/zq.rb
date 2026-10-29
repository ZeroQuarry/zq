# Homebrew formula for the zq companion CLI.
#
# After cutting a release, update `version`/`sha256` (SHA256SUMS ships
# with each release), then push to the ZeroQuarry/homebrew-tap repo so
# `brew install zeroquarry/tap/zq` works. Until the tap exists, users
# can install straight from this file:
#
#   brew install ./dist/zq.rb
class Zq < Formula
  desc "ZeroQuarry companion CLI: credential ingest without the web app"
  homepage "https://github.com/ZeroQuarry/zq"
  version "0.1.0"

  if OS.mac?
    if Hardware::CPU.arm?
      url "https://github.com/ZeroQuarry/zq/releases/download/v#{version}/zq_#{version}_darwin_arm64.tar.gz"
      sha256 "REPLACE_WITH_SHA256SUMS_ENTRY"
    else
      url "https://github.com/ZeroQuarry/zq/releases/download/v#{version}/zq_#{version}_darwin_amd64.tar.gz"
      sha256 "REPLACE_WITH_SHA256SUMS_ENTRY"
    end
  else
    if Hardware::CPU.arm?
      url "https://github.com/ZeroQuarry/zq/releases/download/v#{version}/zq_#{version}_linux_arm64.tar.gz"
      sha256 "REPLACE_WITH_SHA256SUMS_ENTRY"
    else
      url "https://github.com/ZeroQuarry/zq/releases/download/v#{version}/zq_#{version}_linux_amd64.tar.gz"
      sha256 "REPLACE_WITH_SHA256SUMS_ENTRY"
    end
  end

  def install
    bin.install "zq"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/zq version")
  end
end
