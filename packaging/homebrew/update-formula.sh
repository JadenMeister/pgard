#!/usr/bin/env bash
# Rewrites the url and sha256 of a pgard formula for a version that is ALREADY published on npm.
# Usage: packaging/homebrew/update-formula.sh <version> [formula-file]
# It downloads the registry tarball and checks it before it writes anything:
#   1. against the sha512 integrity value the registry reports (dist.integrity). This is the
#      registry vouching for itself, not an independent check;
#   2. the registry's attestation document must exist and its claims (subject sha512, repository,
#      workflow file, tag) must match the tarball (verify-provenance.mjs). That JSON is unsigned as
#      far as this step is concerned, so it is a consistency check, not a verification;
#   3. an independent root of trust, at least one of:
#        a. `gh attestation verify` on the Sigstore bundle: checks the signature and the signing
#           identity (repository, release workflow, tag, GitHub-hosted runner). Needs the GitHub CLI.
#        b. EXPECTED_SHA256=<hex>: the sha256 the release run printed in its GitHub run summary
#           (the publish job prints it again for the artifact it publishes), compared with the file.
# If neither 3a nor 3b happened, the script exits 1 and does not touch the formula. The one way
# around that is PGARD_I_ACCEPT_UNVERIFIED_PROVENANCE=1, which prints a loud warning.
# Then it writes the sha256 it computed. It publishes and installs nothing.
set -euo pipefail

version="${1:?usage: update-formula.sh <version> [formula-file]}"
formula="${2:-$(dirname "$0")/pgard.rb}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || { echo "not a version: $version" >&2; exit 2; }
[ -f "$formula" ] || { echo "no such file: $formula" >&2; exit 2; }

registry="https://registry.npmjs.org/"
npm_view() { npm view --registry="$registry" "$@"; }
fetch() { curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' "$@"; }

url="https://registry.npmjs.org/pgard/-/pgard-${version}.tgz"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fetch "$url" -o "$tmp/pgard.tgz"

sum="$(shasum -a 256 "$tmp/pgard.tgz" | cut -d' ' -f1)"
expected="$(npm_view "pgard@${version}" dist.integrity)"
actual="sha512-$(openssl dgst -sha512 -binary "$tmp/pgard.tgz" | openssl base64 -A)"
if [ "$expected" != "$actual" ]; then
  echo "integrity mismatch: registry says $expected, downloaded file is $actual" >&2
  exit 1
fi
echo "registry integrity: the tarball matches dist.integrity (the registry's own value, not independent)"

# L3 (#358): step 2, claims in the registry's attestation document.
attestations_url="$(npm_view "pgard@${version}" dist.attestations.url 2>/dev/null || true)"
if [ -z "$attestations_url" ]; then
  echo "pgard@${version} has no provenance attestation on the registry; refusing to update the formula" >&2
  exit 1
fi
fetch "$attestations_url" -o "$tmp/attestations.json"
node "$(dirname "$0")/verify-provenance.mjs" "$tmp/attestations.json" "$tmp/pgard.tgz" "$version"

# Step 3: an independent root of trust.
independent=""
if [ -n "${EXPECTED_SHA256:-}" ]; then
  if [ "$(printf '%s' "$EXPECTED_SHA256" | tr 'A-F' 'a-f')" != "$sum" ]; then
    echo "sha256 mismatch: the release run recorded $EXPECTED_SHA256, the downloaded file is $sum" >&2
    exit 1
  fi
  echo "release run sha256: the tarball matches EXPECTED_SHA256 (independent of the registry)"
  independent="EXPECTED_SHA256"
fi
if command -v gh >/dev/null 2>&1; then
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
    --source-ref "refs/tags/v${version}" \
    --deny-self-hosted-runners \
    --digest-alg sha512
  echo "gh attestation verify: the signature and the signing identity were verified"
  independent="${independent:+$independent and }gh attestation verify"
else
  echo "gh attestation verify: NOT RUN (the GitHub CLI is not installed)" >&2
fi
if [ -z "$independent" ]; then
  if [ "${PGARD_I_ACCEPT_UNVERIFIED_PROVENANCE:-}" = "1" ]; then
    echo "WARNING: PGARD_I_ACCEPT_UNVERIFIED_PROVENANCE=1: nothing independent of the registry checked this tarball." >&2
    echo "WARNING: only the registry's own, unsigned claims were compared. Do not release this formula on that basis." >&2
  else
    echo "refusing to update the formula: nothing independent of the registry verified this tarball." >&2
    echo "Install the GitHub CLI (gh) so the signature is verified, or pass EXPECTED_SHA256=<hex> copied from the GitHub run summary." >&2
    exit 1
  fi
fi

sed -i.bak -E \
  -e "s#^(  url \").*(\")#\1${url}\2#" \
  -e "s#^(  sha256 \")[0-9a-f]{64}(\")( \# placeholder.*)?#\1${sum}\2#" \
  "$formula"
rm -f "$formula.bak"
echo "formula: $formula"
echo "url:     $url"
echo "sha256:  $sum"
echo "verified by: ${independent:-NOTHING (override accepted)}"
