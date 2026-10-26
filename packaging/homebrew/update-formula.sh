#!/usr/bin/env bash
# Rewrites the url and sha256 of a pgard formula for a version that is ALREADY published on npm.
# Usage: packaging/homebrew/update-formula.sh <version> [formula-file]
# It downloads the registry tarball, checks it against the sha512 integrity value the registry
# reports, and writes the sha256 it computed. It publishes and installs nothing.
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

sed -i.bak -E \
  -e "s#^(  url \").*(\")#\1${url}\2#" \
  -e "s#^(  sha256 \")[0-9a-f]{64}(\")( \# placeholder.*)?#\1${sum}\2#" \
  "$formula"
rm -f "$formula.bak"
echo "formula: $formula"
echo "url:     $url"
echo "sha256:  $sum"
