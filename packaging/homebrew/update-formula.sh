#!/usr/bin/env bash
# Rewrites the url and sha256 of a pgard formula for a version that is ALREADY published on npm.
# Usage: packaging/homebrew/update-formula.sh <version> [formula-file]
# It downloads the registry tarball and checks it three ways before it writes anything:
#   1. against the sha512 integrity value the registry reports (dist.integrity);
#   2. against the subject digest of the release's SLSA provenance statement (the registry's
#      attestation document, written by the release workflow run, not by the registry), together
#      with the repository, workflow file and tag that statement names (verify-provenance.mjs);
#   3. with `gh attestation verify` on the Sigstore bundle, when the GitHub CLI is installed.
# EXPECTED_SHA256=<hex> additionally compares the sha256 the release run printed in its summary.
# Then it writes the sha256 it computed. It publishes and installs nothing.
set -euo pipefail

version="${1:?usage: update-formula.sh <version> [formula-file]}"
formula="${2:-$(dirname "$0")/pgard.rb}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "not a version: $version" >&2; exit 2; }
[ -f "$formula" ] || { echo "no such file: $formula" >&2; exit 2; }

url="https://registry.npmjs.org/pgard/-/pgard-${version}.tgz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl --fail --silent --show-error --location "$url" -o "$tmp/pgard.tgz"

sum="$(shasum -a 256 "$tmp/pgard.tgz" | cut -d' ' -f1)"
expected="$(npm view "pgard@${version}" dist.integrity)"
actual="sha512-$(openssl dgst -sha512 -binary "$tmp/pgard.tgz" | openssl base64 -A)"
if [ "$expected" != "$actual" ]; then
  echo "integrity mismatch: registry says $expected, downloaded file is $actual" >&2
  exit 1
fi

# L3 (#358): the registry's own sha512 is not independent of the registry. The provenance
# statement is signed by the release workflow's identity, so its digest is.
attestations_url="$(npm view "pgard@${version}" dist.attestations.url 2>/dev/null || true)"
if [ -z "$attestations_url" ]; then
  echo "pgard@${version} has no provenance attestation on the registry; refusing to update the formula" >&2
  exit 1
fi
curl --fail --silent --show-error --location "$attestations_url" -o "$tmp/attestations.json"
node "$(dirname "$0")/verify-provenance.mjs" "$tmp/attestations.json" "$tmp/pgard.tgz" "$version" "${EXPECTED_SHA256:-}"

if [ "${PGARD_SKIP_GH_ATTESTATION:-}" = "1" ]; then
  echo "gh attestation verify: skipped (PGARD_SKIP_GH_ATTESTATION=1)"
elif command -v gh >/dev/null 2>&1; then
  node -e '
    const fs = require("node:fs");
    const document = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const entry = document.attestations.find((a) => a.predicateType === "https://slsa.dev/provenance/v1");
    fs.writeFileSync(process.argv[2], JSON.stringify(entry.bundle) + "\n");
  ' "$tmp/attestations.json" "$tmp/provenance.bundle.json"
  gh attestation verify "$tmp/pgard.tgz" \
    --bundle "$tmp/provenance.bundle.json" \
    --repo JadenMeister/pgard \
    --signer-workflow JadenMeister/pgard/.github/workflows/release.yml \
    --digest-alg sha512
else
  echo "gh attestation verify: skipped (the GitHub CLI is not installed); the digest checks above passed"
fi

sed -i.bak -E \
  -e "s#^(  url \").*(\")#\1${url}\2#" \
  -e "s#^(  sha256 \")[0-9a-f]{64}(\")( \# placeholder.*)?#\1${sum}\2#" \
  "$formula"
rm -f "$formula.bak"
echo "formula: $formula"
echo "url:     $url"
echo "sha256:  $sum"
