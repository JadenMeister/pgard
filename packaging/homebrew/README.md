# Homebrew formula

`pgard.rb` is a template for the Homebrew formula of PGARD. It installs the npm registry tarball of the `pgard` package and depends on Homebrew's `node`. The formula lives in a separate **tap** repository, not in this one. This directory holds the template, a helper script and the source of the tap's update workflow (`tap-workflow/`). Nothing here creates the tap or publishes anything.

The tap [`JadenMeister/homebrew-pgard`](https://github.com/JadenMeister/homebrew-pgard) is live. Users install with:

```sh
brew tap jadenmeister/pgard   # once
brew trust --formula jadenmeister/pgard/pgard   # once
brew install pgard
```

Recent Homebrew refuses formulae from an untrusted third-party tap until they are trusted; `--formula` trusts only this formula, not the whole tap. If `brew install` says the `brew link` step failed because `bin/pgard` already exists, a global npm install of pgard is in the way: `npm uninstall -g pgard`, then `brew link pgard`.

`brew tap jadenmeister/pgard` adds `JadenMeister/homebrew-pgard`. After that the short name works for install and `brew upgrade pgard`. The one-line form `brew install jadenmeister/pgard/pgard` taps automatically but still needs the trust step. A bare `brew install pgard` without the tap only works once the formula is in homebrew-core, which requires Homebrew's notability criteria and is not planned.

## Create the tap repository (done once, by the owner; kept for reference)

1. On GitHub create a **public** repository named exactly `homebrew-pgard` under `JadenMeister`. Homebrew maps `jadenmeister/pgard` to `JadenMeister/homebrew-pgard`.
2. Add a `Formula/` directory and copy `pgard.rb` to `Formula/pgard.rb`.
3. Wait until the first version is on npm (see [docs/RELEASING.md](../../docs/RELEASING.md)), then run the update script below so that `url` and `sha256` are real. A formula with the placeholder checksum does not install.
4. Commit and push to the tap's default branch.

## Automatic update PRs (tap workflow)

The tap repository opens the update PR for each new npm version by itself. The workflow's source is [`tap-workflow/update-formula.yml`](tap-workflow/update-formula.yml) in this repository; it runs in the tap, not here. Nothing is merged automatically.

How it works:

1. A few times a day (and on demand) the workflow reads the formula's version and `npm view pgard dist-tags.latest`. It does nothing when `latest` is not newer, when the version is a pre-release, when the version was published less than 24 hours ago (Homebrew refuses it), or when a branch or PR (open, merged or closed) named `update-pgard-<version>` already exists. The decision is made by [`tap-workflow/next-version.mjs`](tap-workflow/next-version.mjs), which is unit-tested.
2. It runs `update-formula.sh <version> Formula/pgard.rb` from a checkout of this repository at a pinned commit. `gh` is preinstalled on the runner, so `gh attestation verify` runs. If verification fails, the job fails and the formula is not changed, committed or pushed.
3. It pushes the branch `update-pgard-<version>`, commits `pgard <version>` as `github-actions[bot]` and opens a PR whose body holds the verification output and a checklist.
4. A second job on macOS taps the PR branch and runs `brew audit --strict --online`, `brew install --build-from-source` and `brew test`, then comments the result on the PR. A failing job is red but does not remove the PR.
5. **A person reviews and merges the PR.** That is the gate: check that the diff changes only `url` and `sha256`, that the output says `gh attestation verify` passed and that the macOS comment is green.

The workflow uses only the built-in `GITHUB_TOKEN` (no new secrets), starts with `permissions: {}`, and every action and the scripts checkout are pinned to full commit SHAs.

### One-time setup in the tap

1. In the tap repository, Settings, Actions, General, Workflow permissions: tick **Allow GitHub Actions to create and approve pull requests** (the owner has turned this on).
2. Merge the change that contains `tap-workflow/` into `main` of this repository and note the full 40-character commit SHA of a merged commit.
3. Copy `packaging/homebrew/tap-workflow/update-formula.yml` to `.github/workflows/update-formula.yml` in the tap. Replace the single token `PGARD_SCRIPTS_SHA_PLACEHOLDER` with that SHA (`grep PGARD_SCRIPTS_SHA_PLACEHOLDER` finds it; the file in this repository must keep the placeholder). The workflow checks out `update-formula.sh`, `verify-provenance.mjs` and `next-version.mjs` at exactly that commit, so bump the SHA by hand when those scripts change.
4. Commit it to the tap's default branch. Scheduled workflows only run from the default branch.

### Run it manually

In the tap, Actions, `update-formula`, Run workflow. Leave `version` empty for npm's latest, or give `x.y.z` for a specific version. The same checks apply (newer than the formula, at least a day old, no existing branch or PR). A version whose PR was closed without merging counts as handled: reopen that PR, or update the formula by hand (below).

### When verification fails

The run is red and the formula is untouched. Read the failing step: a mismatch between the tarball and the registry's integrity or attestation, a failing `gh attestation verify`, or a version without provenance. Do not bypass it: do not set `PGARD_I_ACCEPT_UNVERIFIED_PROVENANCE` in the workflow. Check the release run of that version in this repository first; if the release itself is wrong, deprecate the version and release a fix (see [docs/RELEASING.md](../../docs/RELEASING.md)). If the script or the registry's format changed, fix `update-formula.sh` here, merge it and bump the SHA in the tap's workflow.

## Update the formula by hand (fallback)

The workflow replaces this for normal releases. Use it when the workflow is not installed or has to be bypassed. After `npm publish` has finished and `npm view pgard@<version>` shows the version:

```sh
packaging/homebrew/update-formula.sh <version> /path/to/homebrew-pgard/Formula/pgard.rb
```

The script downloads `https://registry.npmjs.org/pgard/-/pgard-<version>.tgz` (https only) and writes the new `url` and its `sha256` into the formula only after the checks below pass. Without the second argument it edits the template next to it. The first two are consistency checks against data the registry serves; **the update needs a third check that does not depend on the registry**, and the script exits 1 without touching the formula if there is none.

1. **Registry integrity (not independent).** The tarball must match the `dist.integrity` (sha512) that the registry reports. This proves only that the download is what the registry serves.
2. **Provenance claims (not a verification).** The registry's attestation document for the version (`npm view pgard@<version> dist.attestations.url`) holds the SLSA provenance statement written by the release run. `verify-provenance.mjs` checks that its subject (`pkg:npm/pgard@<version>`) has the same sha512 digest as the tarball and that it names the repository `https://github.com/JadenMeister/pgard`, the workflow `.github/workflows/release.yml` and the ref `refs/tags/v<version>`. The JSON is not signed as far as this step is concerned: anyone who can alter the registry's responses can forge a statement that passes it. A version without a provenance attestation is refused.
3. **An independent root of trust, at least one of:**
   - **`gh attestation verify`** (runs automatically when the GitHub CLI is installed). The script extracts the Sigstore bundle of that statement and runs `gh attestation verify <tarball> --bundle <bundle> --repo JadenMeister/pgard --signer-workflow JadenMeister/pgard/.github/workflows/release.yml --source-ref refs/tags/v<version> --deny-self-hosted-runners --digest-alg sha512`, which verifies the signature and the signing identity: the repository, the release workflow, the tag and a GitHub-hosted runner. If it fails, the script stops. `npm audit signatures` in a project that depends on `pgard` is an alternative check of the same signature.
   - **`EXPECTED_SHA256=<hex>`**: the sha256 of the tarball taken from the GitHub run summary of the release (the `verify` job prints the tarball it built, the `publish` job prints the bytes it published). The GitHub run page is a different root from the registry. Run `EXPECTED_SHA256=<hex> packaging/homebrew/update-formula.sh <version> ...`.

With neither, the script refuses. The only way around is the loudly named `PGARD_I_ACCEPT_UNVERIFIED_PROVENANCE=1`, which writes the formula after printing a warning that only the registry's own claims were compared; do not release a formula on that basis.

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
