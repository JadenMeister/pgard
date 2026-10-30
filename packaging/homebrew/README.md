# Homebrew formula

`pgard.rb` is a template for the Homebrew formula of PGARD. It installs the npm registry tarball of the `pgard` package and depends on Homebrew's `node`. The formula lives in a separate **tap** repository, not in this one. This directory only holds the template and a helper script. Nothing here creates the tap or publishes anything.

Users install it after the first release with:

```sh
brew tap jadenmeister/pgard   # once
brew install pgard
```

`brew tap jadenmeister/pgard` adds `JadenMeister/homebrew-pgard`. After that the short name works for install and `brew upgrade pgard`. The one-line form `brew install jadenmeister/pgard/pgard` taps automatically. A bare `brew install pgard` without the tap only works once the formula is in homebrew-core, which requires Homebrew's notability criteria and is not planned for the first release.

## Create the tap repository (once, by the owner)

1. On GitHub create a **public** repository named exactly `homebrew-pgard` under `JadenMeister`. Homebrew maps `jadenmeister/pgard` to `JadenMeister/homebrew-pgard`.
2. Add a `Formula/` directory and copy `pgard.rb` to `Formula/pgard.rb`.
3. Wait until the first version is on npm (see [docs/RELEASING.md](../../docs/RELEASING.md)), then run the update script below so that `url` and `sha256` are real. A formula with the placeholder checksum does not install.
4. Commit and push to the tap's default branch.

## Update the formula for each release

After `npm publish` has finished and `npm view pgard@<version>` shows the version:

```sh
packaging/homebrew/update-formula.sh <version> /path/to/homebrew-pgard/Formula/pgard.rb
```

The script downloads `https://registry.npmjs.org/pgard/-/pgard-<version>.tgz` and writes the new `url` and its `sha256` into the formula only after three checks pass. Without the second argument it edits the template next to it.

1. **Registry integrity.** The tarball must match the `dist.integrity` (sha512) that the registry reports. This alone proves only that the download is what the registry serves.
2. **Provenance statement.** The registry's attestation document for the version (`npm view pgard@<version> dist.attestations.url`) holds the SLSA provenance statement written by the release workflow run. `verify-provenance.mjs` checks that its subject (`pkg:npm/pgard@<version>`) has the same sha512 digest as the tarball, and that it names the repository `https://github.com/JadenMeister/pgard`, the workflow `.github/workflows/release.yml` and the ref `refs/tags/v<version>`. A version without a provenance attestation is refused. If you want to compare the sha256 that the release run recorded as well, copy it from the run summary of the `verify` job and run `EXPECTED_SHA256=<hex> packaging/homebrew/update-formula.sh <version> ...`.
3. **Signature.** If the GitHub CLI is installed, the script extracts the Sigstore bundle of that statement and runs `gh attestation verify <tarball> --bundle <bundle> --repo JadenMeister/pgard --signer-workflow JadenMeister/pgard/.github/workflows/release.yml --digest-alg sha512`, which verifies the signature and the certificate identity. Without `gh` the step is skipped with a message (the digest checks in 2 still ran); `PGARD_SKIP_GH_ATTESTATION=1` skips it on purpose. `npm audit signatures` in a project that depends on `pgard` is an alternative check of the same signature.

The script only reads and verifies; it publishes and installs nothing. The provenance and `gh` steps have not run against a real release yet (the first one is not published), so watch the first run and fix the script rather than skipping the check if it disagrees with the registry's format. Then, in the tap repository:

```sh
brew audit --strict --new --online jadenmeister/pgard/pgard   # needs the tap installed locally
brew install --build-from-source jadenmeister/pgard/pgard
brew test jadenmeister/pgard/pgard                            # runs `pgard --version`
git commit -am "pgard <version>" && git push
```

Do these checks before you push if you can: the tap is what users install from. The `test do` block runs `pgard --version` and expects the formula version in its output.

## Notes

- The formula follows the current Homebrew convention for npm formulae: `system "npm", "install", *std_npm_args` and a symlink of the package's `bin` entries into the Homebrew `bin`. `std_npm_args` makes npm install the downloaded tarball into the formula's `libexec`, with `bin` links under `libexec/bin`.
- PGARD has native optional dependencies (`@napi-rs/keyring` ships one prebuilt binary per platform). If `brew audit` or the install complains about binaries for other platforms, follow Homebrew's `node` formula guidance for removing or relinking them in the tap.
- Homebrew runs npm with `--min-release-age=1`: it refuses a package version that was published less than a day ago. If a dependency was published less than a day before the PGARD release, `brew install` fails until that day has passed. Wait a day before updating the tap, and exact-pin and check the dependencies' publish dates when you bump them.
- The `license` is MIT. The version in `url` must match the version the CLI reports, because `test do` compares them.
