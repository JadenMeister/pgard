# Template for the Homebrew tap formula (tap repo: JadenMeister/homebrew-pgard, file Formula/pgard.rb).
# Do not edit the url or sha256 by hand: run packaging/homebrew/update-formula.sh <version>
# after that version is published to npm. See packaging/homebrew/README.md.
class Pgard < Formula
  desc "Local security checks for GitHub projects you are authorized to scan"
  homepage "https://github.com/JadenMeister/pgard"
  url "https://registry.npmjs.org/pgard/-/pgard-0.1.0.tgz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000" # placeholder until the first release
  license "MIT"

  depends_on "node"

  def install
    system "npm", "install", *std_npm_args
    bin.install_symlink libexec.glob("bin/*")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/pgard --version")
  end
end
