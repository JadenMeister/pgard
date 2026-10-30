# Releasing PGARD

> [한국어](RELEASING.ko.md) translation available. This English file is the reference; the translation follows it.

PGARD ships as one npm package, `pgard` (built from `packaging/pgard/package.json` by `npm run pack:pgard`). A release is a version tag; the [`release` workflow](../.github/workflows/release.yml) verifies it, waits for a human approval and publishes the verified tarball to npm with provenance. Homebrew follows from the published tarball.

## What is in the package (dependencies and licenses)

`npm run pack:pgard` bundles the CLI, the dashboard server, the source-analysis worker and the pure-JavaScript third-party dependencies (the TypeScript compiler, `pdfkit` with `fontkit`, `@vue/compiler-sfc` with `postcss` and `@babel/parser`, and their transitive dependencies) into a few files under `dist/` with esbuild. The versions that go in are the ones `package-lock.json` resolves on the release machine (`npm ci`), so they are locked when the tarball is built: a malicious patch release of a transitive dependency published afterwards cannot reach anyone who installs `pgard` ([#358](https://github.com/JadenMeister/pgard/issues/358)).

Two packages stay external and are the only `dependencies` of the published `package.json`, both exact pins: `@napi-rs/keyring` (native, one prebuilt binary per platform, installed by npm as optional packages) and `web-tree-sitter` (its WebAssembly runtime is loaded by file path). The tree-sitter grammars (`.wasm`), the PDF fonts and the dashboard client are copied to `assets/` and checked against pinned SHA-256 values at run time. The worker entry (`dist/source-worker.js`) and the picker's inspector child (`dist/inspector.js`) are separate entry points. No source maps are shipped (a source map would carry the build machine's file paths and the unminified sources); the bundle is not minified, so `dist/` stays readable for review.

The pack step fails, and nothing is packed, when:

- the `dependencies` of `packaging/pgard/package.json` are not exactly the two external packages with the workspaces' versions;
- a bundled package has no license text (`LICENSE`, `COPYING` or `NOTICE` in its npm tarball), declares no license, or declares one that is not on the allowlist in `scripts/pack-licenses.mjs` (MIT, ISC, BSD-2-Clause, BSD-3-Clause, Apache-2.0, 0BSD, BlueOak-1.0.0, CC0-1.0, Python-2.0, and SPDX expressions where an allowed license satisfies the choice). A copyleft or unknown license is never bundled silently: the owner decides, then extends the allowlist in a reviewed change. Packages whose tarball lacks a license field or file are listed with their exact version in `LICENSE_OVERRIDES` in the same file; a new version of such a package fails until someone looks at it again;
- the bundle imports anything that is neither a `node:` built-in nor a declared dependency, or loads a module by a computed path in code that is not on the reviewed allowlist (`ALLOWED_DYNAMIC_USES` in `scripts/pack-lib.mjs`, each entry with the reason it cannot run in PGARD, for example the TypeScript language-service plugin loader);
- one of the path rewrites for `import.meta.url` asset lookups or the pdfkit and `@vue/compiler-sfc` patches in `scripts/pack-pgard.mjs` no longer matches exactly (an upgrade of those packages needs a look at the patch).

The shipped `NOTICE.md` is the repository's `NOTICE.md` plus a generated section, "Bundled npm packages", with every bundled package, its version, its license and its license text. It is generated from the files that actually went into the bundle, so it needs no manual upkeep. When you upgrade a dependency, run `npm run pack:pgard` and `npm run smoke:pack`: the smoke test installs the tarball and scans a JavaScript, a Vue and a Python project, writes JSON, SARIF, HTML and PDF output, runs `precommit` and the dashboard from the installed package.

The analyzer hash (`packages/scan-core/src/analyzer-hash.ts`) is computed from sources at build time by `scripts/analyzer-hash.mjs` and compiled into the bundle as a constant, so bundling does not change how it works. It also covers the declared and resolved versions of the parsers and compilers the analyzers run on, so a dependency bump in `package-lock.json` still makes the next scan a full one.

## Versioning

PGARD uses [Semantic Versioning](https://semver.org). The version number covers everything a user or a script can depend on. **A change is breaking** (major bump after 1.0) when it changes any of these in a way an existing user or script can notice:

- **CLI commands and flags.** Removing or renaming a command or option, changing what a flag does or its accepted values, or making an optional flag required. Adding a command or an optional flag is not breaking.
- **JSON result schema.** The `schemaVersion` of the scan result follows [RESULT_SCHEMA.md](RESULT_SCHEMA.md): a minor schema bump (additive, optional) is a minor release, a major schema bump (`1.x` to `2.0`) is a breaking release.
- **SARIF output.** Removing or renaming a field, changing how a rule id, level, location or fingerprint is written, or leaving SARIF 2.1.0. Adding fields is not breaking.
- **Exit codes.** Changing the meaning of 0, 2, 3, 4, 5 or 130, or an existing situation that returns a different code. A new code for a situation that was an internal error before is breaking too.
- **Configuration file keys.** Removing, renaming or re-typing a `pgard.config.json` key, or changing its default so results change. Adding an optional key is not breaking.
- Also breaking: raising the minimum Node.js version beyond a patch of the supported lines, and dropping an operating system.

Not breaking: new rules and findings, text and wording, report layout, performance, security fixes of the scanner's own behaviour. A new rule can change a user's findings, so list it under Added.

**Pre-1.0 policy (now).** While the version is `0.y.z`, a breaking change bumps the minor (`0.1.0` to `0.2.0`) and is marked **BREAKING** in the changelog; patch releases (`0.1.1`) only fix bugs and never break. After `1.0.0` the normal rules apply. `1.0.0` waits until the CLI flags, the result schema, SARIF and the exit codes are considered stable.

Pre-release versions (`0.2.0-rc.1`) are allowed. The workflow publishes them under the npm dist-tag `next`, never `latest`.

## One-time setup (repository owner)

The workflow is safe to merge before any of this exists (see "What happens when nothing is configured"). Before the first release:

1. **GitHub environment.** Settings, Environments, New environment `npm-publish`. Add **Required reviewers** (yourself and anyone who may approve a release), turn on "Prevent self-review" only if there is a second reviewer, and limit **Deployment branches and tags** to `main` and the tag pattern `v*.*.*`. Reference: [Managing environments for deployment](https://docs.github.com/en/actions/managing-workflow-runs-and-deployments/managing-deployments/managing-environments-for-deployment).
2. **npm trusted publisher.** The npm name `pgard` is already reserved by a placeholder (0.0.1), so it exists and can be configured. On npmjs.com open the package, Settings, Trusted Publisher, GitHub Actions, and enter: owner `JadenMeister`, repository `pgard`, workflow filename `release.yml` (the file name only), environment `npm-publish`. Under **Allowed actions** tick **npm publish**: configurations created after 3 September 2026 allow only `npm stage publish` by default, and the workflow runs a direct `npm publish`. (`npm stage publish` is an option if you prefer an extra 2FA approval on npm before a version goes live; the workflow would then need to call it instead.) **Fill in the environment field even though npm marks it optional.** The security model relies on it: npm accepts the OIDC token only if the workflow run's environment matches. If a tag's commit dropped `environment:` from the workflow (skipping the approval), npm would reject the token only when the configuration names the environment. All fields are case-sensitive and npm does not validate them when you save: an error only appears at publish time. A new configuration that has no successful publish within two days expires. Reference: [npm trusted publishing](https://docs.npmjs.com/trusted-publishers).
3. **Tag ruleset.** Settings, Rules, Rulesets: add a tag ruleset for `v*` that restricts who can create, update and delete these tags (and blocks force pushes), so only maintainers can start a release. The workflow additionally refuses a commit that is not on `main`.
4. **Homebrew tap** (after the first publish): see [packaging/homebrew/README.md](../packaging/homebrew/README.md).

**Token fallback.** If trusted publishing cannot be used (for example a self-hosted runner), create a granular npm access token limited to the `pgard` package with publish permission, store it as the environment secret `NPM_TOKEN` of `npm-publish`, and add `NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}` to the `env:` of the publish step. Keep `--provenance`. A token is a long-lived credential, so prefer OIDC.

## What happens when nothing is configured

- The workflow runs only for `v*.*.*` tags and by hand, never for branches or pull requests, so merging it publishes nothing.
- If the `npm-publish` environment does not exist, GitHub **creates it on the first run with no protection rules**: the publish job then starts without approval. That is why nothing may depend on the environment alone. Publishing still fails, because without a trusted publisher on npm (or an `NPM_TOKEN`) npm rejects the OIDC token or the missing login and nothing is published. Provenance also needs a public repository and `id-token: write` on a GitHub-hosted runner, which the job has.
- To avoid even that run, do the setup above **before** pushing the first tag, and use the manual dispatch with `dry_run` first.

## Release checklist

1. **Start from a green `main`.** All merged PRs for the release are in; CI is green.
2. **Choose the version** using the rules above.
3. **Bump the version** in both places, which must agree (the pack step and the workflow fail otherwise):
   - `packaging/pgard/package.json` (`version`)
   - `packages/scan-core/src/version.ts` (`PGARD_VERSION`)
4. **Update `CHANGELOG.md`.** Rename `## [Unreleased]` content to `## [X.Y.Z] - YYYY-MM-DD`, start a fresh empty `## [Unreleased]`, and update the compare links at the bottom. Group entries under Added, Changed, Fixed, Security (and Removed, Deprecated if needed). Mark breaking changes **BREAKING**.
5. **Open a PR** `chore(release): vX.Y.Z` with only these changes, review it, and merge it. Run locally before: `npm run check`, `npm run corpus:check`, `npm run pack:pgard`, `npm run smoke:pack`. If dependencies changed since the last release, read the license count `pack:pgard` prints and the new entries of the "Bundled npm packages" section in the packed `NOTICE.md`.
6. **Dry run (recommended).** Actions, `release`, Run workflow on `main` with the version and `dry_run` ticked. It verifies everything and runs `npm publish --dry-run`; nothing is published. The dry run still uses the `publish` job, so it **also waits for the `npm-publish` approval and requests an OIDC token**. A dispatch on a branch can only be a dry run; a real publish needs a tag.
7. **Tag.** On the merged commit of `main`: `git tag -a vX.Y.Z -m "pgard X.Y.Z"` and `git push origin vX.Y.Z`. Tags are `v` plus the exact version (`v0.1.0`, `v0.2.0-rc.1`); the workflow refuses a tag that does not equal `v` + the package version.
8. **Approve.** The `verify` job builds, runs the gates and uploads the tarball. The `publish` job then waits at the `npm-publish` environment. A required reviewer opens the run, checks that the tag, the commit and the verify results are the intended ones, and approves. The publish job checks the tarball's checksum against the verify job, then runs `npm publish <tarball> --provenance --access public`.
9. **Post-publish checks** (below).
10. **GitHub release.** Create the GitHub release for the tag by hand with the changelog section as its notes.
11. **Homebrew.** Update the tap ([packaging/homebrew/README.md](../packaging/homebrew/README.md)).

## Post-publish checks

```sh
npm view pgard@X.Y.Z version dist.tarball dist.integrity
npm view pgard dist-tags              # latest must be X.Y.Z (next for a pre-release)
```

- Open `https://www.npmjs.com/package/pgard/v/X.Y.Z`: the **Provenance** badge must show the `JadenMeister/pgard` repository, the `release.yml` workflow and the tag's commit. `npm audit signatures` in a project that depends on it verifies the registry signature and the attestation.
- Smoke install in a temporary prefix (nothing global):

  ```sh
  prefix="$(mktemp -d)"
  npm install --prefix "$prefix" pgard@X.Y.Z
  "$prefix/node_modules/.bin/pgard" --version      # pgard X.Y.Z
  "$prefix/node_modules/.bin/pgard" doctor
  rm -rf "$prefix"
  ```

- Check that `npx pgard@X.Y.Z --version` works from a clean directory.
- Check that the tarball is the one the release run built, not only the one the registry reports: `packaging/homebrew/update-formula.sh X.Y.Z` does this before it touches the formula (see [packaging/homebrew/README.md](../packaging/homebrew/README.md)). It compares the downloaded tarball with the subject digest of the provenance statement and runs `gh attestation verify`. The `verify` job also prints the tarball's sha256 in the run summary; pass it as `EXPECTED_SHA256=<hex>` to compare that too.

## Rollback

A published version cannot be replaced, and `npm unpublish` is not used (it breaks everyone who depends on the version, and npm limits it). Instead:

```sh
npm deprecate pgard@X.Y.Z "Broken: use X.Y.Z+1 (reason: ...)"
```

`npm deprecate` and `npm dist-tag` are not covered by the OIDC publishing setup: a maintainer runs them locally after an interactive `npm login` (with 2FA).

Then fix forward: release a patch (`X.Y.Z+1`) through the normal checklist. If `latest` points at a bad version and the previous good one must be restored first, move the tag with `npm dist-tag add pgard@<good> latest` (needs a maintainer logged in with publish rights; npm CLI 11.21.0+ also lets a trusted publisher manage dist-tags if that permission is ticked). For a leaked secret or a security problem, deprecate, release the fix and say so in the changelog's Security section. Update the Homebrew tap to the fixed version, or revert its last commit.
