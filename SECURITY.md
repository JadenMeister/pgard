# Security policy

PGARD is a security tool that handles GitHub sign-in tokens, repository metadata and your source code on your own computer. We take reports about PGARD itself seriously.

## Reporting a vulnerability

Please report vulnerabilities **privately**. Do not open a public issue or pull request for them.

1. Open the [Security tab](https://github.com/JadenMeister/pgard/security) of this repository.
2. Choose **Report a vulnerability** to use GitHub's private vulnerability reporting.
3. Describe what you found, the PGARD version (`pgard --version`), your operating system and Node.js version, and the steps to reproduce it. A minimal reproduction helps most.

If the **Report a vulnerability** button is not available to you, open a public issue that says only that you have a security report and asks for a private channel. Do not put technical details in that issue. A maintainer will reply with a way to share the details.

We aim to acknowledge a report within a few days and to tell you what we decided. PGARD is maintained by a small team, so these are goals, not guarantees. Please give us a reasonable time to fix the problem before you publish it. We are happy to credit you in the fix if you wish.

## Scope

In scope, for the latest code on `main` and the latest release once one exists:

- Bypassing or weakening the authorization gate (owner approval, current access, contribution, or the rule that it runs again on every scan).
- Leaking or mishandling the GitHub token, or secret values that PGARD should redact.
- The local dashboard: its `127.0.0.1` binding, session token, `Host` and `Origin` checks, Content-Security-Policy, and anything that lets a web page or another local user read or drive it.
- The local web checks sending anything other than anonymous `GET` or `HEAD` requests to `127.0.0.1`.
- Reading or writing files outside what PGARD documents, unsafe handling of stored results, reports, symbolic links or paths.
- Anything that makes PGARD send your code, lockfile contents or results off your computer. This includes `pgard scan` and `pgard sbom`, which must contact GitHub only (sign-in and authorization metadata).
- `pgard advisories update` contacting any host other than `osv-vulnerabilities.storage.googleapis.com`, sending anything, running during a scan, or accepting a download that fails its integrity checks (zip structure, per-record checksums, size and time limits, the replayed-archive guard). The download has no published checksum, so its integrity rests on https to that pinned host; see the README section "Privacy and network traffic".

Out of scope:

- A scan that misses a vulnerability, or reports one that is not real. PGARD says that its findings are signals and that detection is not complete. Please report these as normal issues, with a sample if you can.
- Vulnerabilities in other software that PGARD scans, or in GitHub, your operating system, or your keychain.
- Problems that need an attacker who already controls your computer or your GitHub account.
- Reports from automated tools without a working demonstration.
- Denial of service by running PGARD on a huge repository on your own machine.

## Supply chain

What a user installs from npm is meant to be exactly what the release run built, and nothing else.

- **One package, few dependencies.** `pgard` is published from a version tag by the `release` workflow, after a manual approval, with npm provenance (trusted publishing, no long-lived token). The pure-JavaScript third-party dependencies (the TypeScript compiler, `pdfkit`, `@vue/compiler-sfc` and everything they pull in) are **bundled into the package at release time**, so their versions are fixed by `package-lock.json` when the tarball is built. A malicious patch release of one of them, published after our release, does not reach anyone who installs `pgard`. Only two runtime `dependencies` remain, both exact pins: `@napi-rs/keyring` (native keychain access) and `web-tree-sitter` (WebAssembly runtime). They cannot be inlined. Their own dependencies are the exact-pinned optional platform binaries of `@napi-rs/keyring`, and none for `web-tree-sitter`. The package has no install scripts.
- **Reviewable bundle.** The bundle is not minified and ships without source maps. The pack step fails if the bundle imports something undeclared, loads a module by a computed path outside a reviewed allowlist, or includes a package without a license text or with a license outside a permissive allowlist. `NOTICE.md` in the package lists every bundled package with its license text.
- **The cost of bundling.** A fix released upstream for a bundled dependency reaches users only with a new `pgard` release, so a release is due when a dependency has a security fix that affects a code path PGARD runs. The release `verify` job installs from the lockfile (`npm ci`); dependency bumps are normal pull requests with the same review as code.
- **Checking a release.** `npm audit signatures` verifies the registry signature and the provenance attestation. `packaging/homebrew/update-formula.sh`, which the owner runs before the Homebrew formula is updated, compares the tarball with the provenance statement's subject digest, repository, workflow and tag and runs `gh attestation verify`, in addition to the registry's `sha512` value.
- **Homebrew.** The formula installs the same npm tarball and pins its sha256.

A vulnerability in a dependency that PGARD bundles is in scope when it affects PGARD's behavior (for example a parser that can be made to execute scanned code). Please include the `pgard` version you used.

## No bounty

PGARD is a free, open-source project. There is no bug bounty program and no payment for reports. We are grateful for them anyway.

## Supported versions

PGARD is in the 0.x series. Until 1.0, only the latest 0.x minor release receives security fixes; fixes also go to `main`. Please update to the latest release before reporting a problem you found in an older one.
