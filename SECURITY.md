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

## No bounty

PGARD is a free, open-source project. There is no bug bounty program and no payment for reports. We are grateful for them anyway.

## Supported versions

PGARD is in the 0.x series. Until 1.0, only the latest 0.x minor release receives security fixes; fixes also go to `main`. Please update to the latest release before reporting a problem you found in an older one.
