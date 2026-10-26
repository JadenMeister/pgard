# PGARD

[![CI](https://img.shields.io/github/actions/workflow/status/JadenMeister/pgard/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white)](https://github.com/JadenMeister/pgard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/JadenMeister/pgard?color=blue)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-22.23.4%20%7C%2024.22.1%20%7C%2026.12.1-339933?logo=nodedotjs&logoColor=white)](#requirements)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)](tsconfig.base.json)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey?logo=apple&logoColor=white)](#requirements)
[![Status: MVP](https://img.shields.io/badge/status-MVP-orange)](#out-of-scope-for-the-mvp)
[![Data stays local](https://img.shields.io/badge/data-stays%20local-2ea44f)](#privacy-and-network-traffic)
[![Last commit](https://img.shields.io/github/last-commit/JadenMeister/pgard/main)](https://github.com/JadenMeister/pgard/commits/main)

English | [한국어](README.ko.md)

PGARD (`pgard`) is a local security scanner for GitHub projects you are authorized to scan. It runs on your own computer as a command-line tool and a local web dashboard. It checks the current code and configuration, the Git history, and (optionally) a web service you run on `127.0.0.1`. Findings are decided from the code itself; PGARD does not ship or query a vulnerability database (see [Code-based analysis](#code-based-analysis)).

Before every scan, PGARD checks that the repository owner approved PGARD, that you currently have access to the repository, and that you own it or really contributed to it. Your code and the results stay on your computer.

PGARD is an MVP. It does not find every vulnerability, and "no findings" never means "secure".

> **Current status:** PGARD ships the client id of the PGARD GitHub App, so signing in needs no setup. A scan still needs the App installed on the account that owns the repository: your personal account, or an organization you own (see [Authorization model](#authorization-model)).

PGARD is released under the [MIT License](LICENSE).

## Contents

- [Requirements](#requirements)
- [Install and build](#install-and-build)
- [Commands](#commands)
- [Authorization model](#authorization-model)
- [Scan scopes and coverage](#scan-scopes-and-coverage)
- [Analyzers and rules](#analyzers-and-rules)
- [Code-based analysis](#code-based-analysis)
- [Local web checks](#local-web-checks)
- [Git history checks](#git-history-checks)
- [Results and reports](#results-and-reports)
- [Dashboard](#dashboard)
- [Privacy and network traffic](#privacy-and-network-traffic)
- [Out of scope for the MVP](#out-of-scope-for-the-mvp)
- [Known limitations](#known-limitations)
- [Development](#development)
- [License](#license)

## Requirements

- Node.js 22.23.4, 24.22.1 or 26.12.1, or a newer patch on the same line. These are the releases that fix the vulnerabilities in the [Node.js security release of 21 October 2026](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases), including a Brotli decoder out-of-bounds write that can lead to remote code execution (CVE-2026-111497) and TLS hostname check bypasses. PGARD uses `fetch` and TLS to call the GitHub API, so older releases are not supported: `pgard doctor` fails the Node.js check on them. Node.js 20 and earlier and the odd-numbered lines get no fixes. Check your version with `node --version`.
- Git
- macOS or Linux for local port discovery (`lsof` on macOS, `/proc/net/tcp*` on Linux). You can always type a port by hand.
- A GitHub account (see [GitHub App and sign-in](#github-app-and-sign-in))

## Install and build

PGARD is not published to npm. Build it from source:

```sh
git clone https://github.com/JadenMeister/pgard.git
cd pgard
npm ci
npm run build          # TypeScript packages and the dashboard UI (Vite)
npm link -w @pgard/cli # optional: puts `pgard` on your PATH
```

Without `npm link`, run `node apps/cli/dist/bin/pgard.js <command>` from the repository.

Then run PGARD from the root of the project you want to scan:

```sh
cd /path/to/your/project
pgard doctor          # check the environment
pgard login           # sign in to GitHub once (saved in the OS keychain)
pgard project verify  # check authorization only
pgard scan            # code + history
```

## Commands

The target is always the **Git root of the current directory**. There is no option to choose another path, host or URL, and no option to skip authorization. Every scan runs the authorization checks again; an earlier `project verify` is never reused.

`pgard --help` prints (excerpt):

```text
Usage:
  pgard                         interactive menu (arrow keys, Enter, Esc, ?)
  pgard project verify          check repository, GitHub identity, owner approval,
                                current access and merged contribution
  pgard scan                    code and configuration + Git history
  pgard scan code               current code and configuration
  pgard scan history            Git history and tracked files (secrets, risky files)
  pgard scan web [--port N]     anonymous read-only checks of a local HTTP service
  pgard scan all [--port N]     code + history + local HTTP service
  pgard dashboard [--target-port N]
                                start the local web dashboard
  pgard rules list [--language js|ts|react|vue|go]
                                supported rules and unsupported areas
  pgard doctor                  diagnose the environment (not an authorization)
  pgard login                   sign in to GitHub once and save it in the OS keychain
  pgard logout                  remove the saved GitHub sign-in from the OS keychain
  pgard --help | <command> --help
  pgard --version
```

| Command                | What it does                                                                                                                                                                                                                                                                                                                                                                                 |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pgard`                | Interactive menu: verify, scans, dashboard, rules, doctor, quit.                                                                                                                                                                                                                                                                                                                             |
| `pgard project verify` | Runs the authorization checks and shows each one (repository, GitHub identity, owner approval, current access, contribution) as passed, failed or unverifiable, with a reason. The result is not stored.                                                                                                                                                                                     |
| `pgard scan`           | `code` + `history`.                                                                                                                                                                                                                                                                                                                                                                          |
| `pgard scan code`      | Current source code and configuration.                                                                                                                                                                                                                                                                                                                                                       |
| `pgard scan history`   | Committed `.env` files and secrets in tracked files and Git history.                                                                                                                                                                                                                                                                                                                         |
| `pgard scan web`       | Anonymous, read-only checks of a local HTTP service on `127.0.0.1` that you confirm.                                                                                                                                                                                                                                                                                                         |
| `pgard scan all`       | `code` + `history` + `web`. If no web target is confirmed, the result is `partial`.                                                                                                                                                                                                                                                                                                          |
| `pgard dashboard`      | Starts the local web dashboard. See [Dashboard](#dashboard).                                                                                                                                                                                                                                                                                                                                 |
| `pgard rules list`     | Lists the rule catalog grouped by scope (code, Git history, local HTTP; a rule with an unknown scope goes under "Other rules") with each rule's severity and languages, the detection criteria version, and the areas PGARD does not cover (including dependency vulnerability lookups, since PGARD ships no vulnerability database). Works outside a project and makes no network requests. |
| `pgard doctor`         | Checks Node.js, Git, GitHub reachability, local port discovery, which GitHub App PGARD signs in with (the built-in PGARD App, or `PGARD_GITHUB_APP_CLIENT_ID` as an override), and whether a GitHub sign-in is saved in the OS keychain (and for which account; never the token). It is a diagnosis only, not an authorization. Works outside a project.                                     |
| `pgard login`          | Signs in to GitHub with the device flow and saves the sign-in in the OS keychain, so later scans and the dashboard reuse it. Running it again replaces the saved sign-in. See [Saved sign-in](#saved-sign-in-os-keychain).                                                                                                                                                                   |
| `pgard logout`         | Removes the saved GitHub sign-in from the OS keychain. See [Saved sign-in](#saved-sign-in-os-keychain).                                                                                                                                                                                                                                                                                      |

`pgard rules list --language <lang>` shows only the rules for that language; rules that apply to any language (Git history and local HTTP rules) are always included, and `--language react` or `vue` also includes the JavaScript/TypeScript rules.

Every command also has its own help, for example `pgard scan --help` or `pgard login --help`. `pgard scan --help` prints (excerpt):

```text
Options:
  --port N                 local service port 1-65535 (web and all only). You
                           still confirm the service identity with y/N.
  --report html|pdf|both   save a report (requires --output-dir)
  --output-dir <dir>       existing directory for the report (requires --report);
                           files are never overwritten; a directory inside the
                           Git repository needs explicit confirmation
  --no-browser             do not open GitHub pages (device sign-in, App
                           install) in the browser; the links are printed.
                           Pages open automatically only when stdout is a
                           terminal

If owner approval is the only failed check and the PGARD GitHub App just needs to
be installed, PGARD opens the install page, waits for it, re-runs the full
authorization and continues the scan.
```

### Options

- `--port N` (`scan web` and `scan all` only): the local service port, an integer from 1 to 65535. You still have to confirm the service.
- `--target-port N` (`dashboard` only): pre-selects the local service to check. You still confirm it in the browser. The dashboard itself runs on its own free port.
- `--report html|pdf|both` and `--output-dir <dir>` (any `scan`): save a report. The two options must be used together. The directory must already exist, and existing files are never overwritten. A directory inside the Git repository needs an explicit `y` (without an interactive terminal it is refused). By default, results are only shown in the terminal.
- `--language js|ts|react|vue|go` (`rules list` only): filter the rule list by language. Rules for any language are always included; `react` and `vue` also include the JavaScript/TypeScript rules.
- `--no-browser` (`scan`, `project verify`, `login`, `dashboard`): do not open GitHub pages (the device sign-in page, the App install page) in the browser; the links are only printed. Without it, PGARD opens them automatically only when stdout is a terminal. The links are always printed too, and a browser that fails to open is not an error.
- `--help` / `-h`, and `pgard --version` / `-V`.

Unknown commands and options, invalid values and invalid combinations are rejected before any Git, GitHub or network activity. An unknown scan type such as `dependencies` exits with code 2 and names the valid ones: `code`, `history`, `web`, `all`.

### Exit codes

| Code | Meaning                                                                                                                                                                             |
| ---- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | The requested scope completed (findings may exist). For `doctor`: the diagnosis completed.                                                                                          |
| 2    | Invalid command, option, value or combination.                                                                                                                                      |
| 3    | The repository, authorization or contribution check failed (the scan was blocked).                                                                                                  |
| 4    | Part of the scan did not run, so the result is partial (for example, no web target was confirmed, or the Git history scan stopped at its time budget), or the report export failed. |
| 5    | Internal error. Details are hidden; set `PGARD_DEBUG=1` to see a sanitized message.                                                                                                 |
| 130  | Cancelled by the user.                                                                                                                                                              |

`doctor` exits with 0 when the diagnosis completed (problems are listed as `[fail]` or `[warn]` rows) and 5 on an internal error. `pgard login` and `pgard logout` use these codes:

| Code | `pgard login`                                                                                                                     | `pgard logout`                                                              |
| ---- | --------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- |
| 0    | Signed in and saved.                                                                                                              | Removed, or nothing was saved.                                              |
| 3    | GitHub sign-in failed, or `PGARD_GITHUB_APP_CLIENT_ID` is not a valid client id (or `PGARD_GITHUB_APP_SLUG` is not a valid slug). | `PGARD_GITHUB_APP_CLIENT_ID` is not a valid client id; nothing was removed. |
| 4    | No OS keychain is available, or saving failed; nothing was saved.                                                                 | No OS keychain is available; nothing was removed.                           |
| 5    | Internal error.                                                                                                                   | Internal error.                                                             |
| 130  | Cancelled.                                                                                                                        |                                                                             |

### Interactive keys

Arrow keys (or `j`/`k`) move, Enter selects, Esc goes back, and `?` shows help. Ctrl+C asks `Cancel and exit? [y/N]`. While a scan or GitHub sign-in is running, press Ctrl+C twice within 5 seconds to cancel (exit code 130).

## Authorization model

PGARD scans a repository only when it has evidence that you are allowed to. Before every scan it reports these checks (in this order):

1. **Repository.** The current directory is the root of a Git repository with valid history. The repository uses only its own objects and history (no alternates, grafts or replace refs), and it has exactly one unambiguous `github.com` remote.
2. **GitHub identity.** You sign in to GitHub with the device flow, or PGARD reuses the sign-in saved in the OS keychain (see below). Only the sign-in is reused: checks 3 to 5 always run against GitHub again.
3. **Owner approval.** For a repository owned by a **personal account**, the PGARD GitHub App is installed on that account and the installation includes this repository. Only the owner of a personal account can install an app on it. For a repository owned by an **organization**, see [Organization repositories](#organization-repositories).
4. **Current access.** GitHub reports that you currently have at least read access to the repository.
5. **Contribution.** If you are the **verified owner**, you do not have to prove a contribution of your own, but your local history must still share a commit with the repository's default branch. For a personal repository, your GitHub account id must equal the repository owner's account id (both come from the GitHub API, never from the remote); the reason reads "`<user>` owns `<owner>/<repo>` (verified by GitHub account id); a separate contribution is not required." For an organization repository, you must be an active owner of the organization, proven by the same membership evidence that owner approval obtained in the same run (no second lookup); the reason reads "`<user>` is an owner of the organization "`<org>`"; a separate contribution is not required." In both cases at least one commit of `HEAD`'s ancestry (newest first, up to the same 30 local commits) must be in the default-branch history on GitHub, checked the same way as for a contribution; this ties the code on disk to the repository, so pointing `origin` at another repository you own does not let you scan unrelated code. A passing reason then ends with "Local HEAD is linked to `<owner>/<repo>` by commit `<sha>`." Unpushed local commits are fine as long as an older commit of `HEAD` is on the default branch. If none links (including an empty repository on GitHub), contribution fails with "None of the last `<N>` local commits is on `<owner>/<repo>`'s default branch "`<branch>`"; the local code can't be tied to this repository. Push or pull so local history shares a commit with the default branch." A GitHub API error while checking this makes contribution `unverifiable`. The exemption applies only when owner approval passed in the same run: any error, mismatch or unknown state means no exemption, and the normal rule below applies. It never replaces owner approval or current access, which must still pass on their own. Everyone else needs a contribution in the default-branch history. A commit counts only if GitHub shows it in the default branch, and either it belongs to a pull request you authored that was merged into the default branch, or GitHub verified its signature and attributes the committer to you. Author names or emails, co-author trailers, unmerged pull requests, pull requests merged into other branches or forks, unsigned direct pushes and local-only commits are never accepted as proof. PGARD examines up to 30 local commits (the ancestry of `HEAD`). If none of them qualifies and more local commits exist, contribution is `unverifiable`. When contribution does not pass, the reason ends with how to qualify: "To qualify, get a pull request merged into "`<default branch>`", or sign your commits (GitHub shows them as Verified) and push them to "`<default branch>`"."

Each check is `passed`, `failed` or `unverifiable`, with a reason. The checks are reported in this order, but they are not evaluated strictly in this order: for example, PGARD reads the repository from GitHub (current access) before it checks owner approval. The scan runs only if every check passed. If any evidence is missing or unclear, the scan is **blocked** (exit code 3) and PGARD reports which check failed and why.

### First run: sign-in, App install, continue

The first `pgard scan` (or `pgard project verify`, or the dashboard) in a repository goes like this:

1. **Sign in.** PGARD prints the code and opens `https://github.com/login/device` in your browser (see `--no-browser`). You enter the code and authorize the PGARD GitHub App.
2. **Install the App, if that is all that is missing.** When owner approval is the only failed check, and it failed only because the PGARD GitHub App is not installed on the owner account or its installation does not include this repository, and you may be the one who can approve (for a personal repository you are the owner; for an organization GitHub shows you as an active owner, or cannot show your role yet), PGARD prints and opens the App's install page, preselected for the owner account and this repository:

   ```text
   https://github.com/apps/<slug>/installations/new/permissions?suggested_target_id=<owner account id>&repository_ids[]=<repository id>
   ```

   On GitHub you choose **Only select repositories** (this repository) or **All repositories** and click **Install**. Meanwhile PGARD prints `Waiting for the PGARD GitHub App to be installed... (press Ctrl+C twice to cancel)` and checks owner approval again every 5 seconds, for up to 10 minutes.

3. **Continue.** As soon as the installation is visible, PGARD runs **all five checks again from scratch**, and only then continues: `scan` scans, `project verify` prints the result.

**Installing the App is the owner's approval, and PGARD cannot do it for you.** PGARD never installs the App, never skips a check and never caches an approval; seeing the installation is not a pass on its own. If access was revoked in the meantime, the new check blocks.

- After 10 minutes without an installation, or when stdout is not a terminal (the link is printed, nothing is awaited), the command is blocked with the usual reason (exit code 3). A confirmed Ctrl+C while waiting cancels (exit code 130).
- The re-checks while waiting use only the existing sign-in (in memory or in the OS keychain) and never start a new device sign-in. If the sign-in is gone, or GitHub answers with a rate limit or an error, PGARD prints `Owner approval could not be confirmed. Running the full authorization again...`, stops waiting and runs the full check, which signs in as usual if needed.
- Before the App is installed on an organization, GitHub usually does not show your membership to the App (403/404). PGARD then guides you anyway and prints `If you are an owner of <org>, install the App on the install page; otherwise ask an owner to install it there: <link>`. This is safe because the guidance never passes anything: only a real owner of the organization can complete the install, and after it appears the full check, including the active-owner membership check, runs again from scratch.
- If GitHub shows that you cannot approve (an organization membership that is not an owner or is pending, or a collaborator on someone else's personal repository), PGARD does not wait or open anything. It prints the reason and `Ask an owner of <account> to install the PGARD GitHub App: <link>`. The link contains only GitHub's numeric ids and is safe to share.
- If any other check also failed, installing the App would not be enough, so no install link is offered.
- If `PGARD_GITHUB_APP_CLIENT_ID` is set without `PGARD_GITHUB_APP_SLUG`, PGARD cannot know which App page to open: the reason is kept and `Set PGARD_GITHUB_APP_SLUG to enable the guided install.` is added. Only `github.com` links are ever offered or opened.

### Organization repositories

An organization repository can be scanned only by an **owner of the organization**. Owner approval passes only when both are true:

- The PGARD GitHub App is installed on the organization account, and that installation includes the repository.
- You are an owner of that organization: GitHub's `GET /user/memberships/orgs/{org}` reports your membership as `state: active` with `role: admin`.

The installation alone is not proof, because organization settings can let repository admins install apps and GitHub does not say who installed it. An active member whose role is not `admin` (for example a plain member or a billing manager) is blocked (`failed`) with the reason "`<user>` is not an owner of `<org>` (role: `<role>`); an organization owner must run the scan." A pending membership is blocked (`failed`) with "`<user>`'s membership in `<org>` is pending, not active; an organization owner with an active membership must run the scan." An outside collaborator is not a member, so GitHub answers 404 and owner approval is `unverifiable` with the 404 reason below. Current access is checked exactly as for personal repositories. Because only an organization owner passes owner approval, that owner is also exempt from a separate contribution (see check 5); a member who is not an owner is blocked at owner approval, and contribution is still evaluated with the normal rule.

When the evidence is unclear, the scan is blocked and owner approval is `unverifiable` with the reason. This includes GitHub answering 403 or 404 for the membership, a rate limit, a network error or an unexpected response, and an organization name in the Git remote that differs from GitHub's (including only in letter case; update the remote to the exact name GitHub shows). A 404 for the membership, which is what an outside collaborator or a non-member gets, is reported as "GitHub did not return `<user>`'s membership in `<org>` (404): `<user>` may not be a member, or the PGARD GitHub App cannot read the organization's members. An owner of `<org>` must run the scan, with the App's Members: Read-only permission approved."

**Required App permission.** Reading the membership needs the organization permission **Members: Read-only** on the PGARD GitHub App (**Organization permissions → Members → Read-only**). The App owner must add it in the App's settings, and every existing organization installation must accept the new permission (an organization owner approves it under the organization's **Settings → GitHub Apps**). Until then GitHub answers 403 and PGARD reports "GitHub refused to show `<user>`'s membership in `<org>` (403): the PGARD GitHub App needs the organization permission Members: Read-only, approved by an owner of `<org>`."

### GitHub App and sign-in

PGARD signs you in through the PGARD GitHub App using the OAuth device flow. The App's client id (`Iv23liKDf0mhnPl2c7zj`) is built in, so there is nothing to set up. A client id is public by design: the device flow needs no client secret, and PGARD has none.

`PGARD_GITHUB_APP_CLIENT_ID` is an optional override for a fork or a GitHub App you registered yourself:

```sh
export PGARD_GITHUB_APP_CLIENT_ID=<client id of your own GitHub App>
```

An empty or whitespace-only value counts as unset. A value that is not a valid client id **blocks**: PGARD never falls back to the built-in App, because owner approval would then be proven against a different App than the one you set. GitHub identity is `unverifiable` with the reason "PGARD_GITHUB_APP_CLIENT_ID is set but is not a valid client id; unset it to use the built-in PGARD App.", scans and `project verify` are blocked (exit code 3), `pgard login` and `pgard logout` exit with 3 (logout removes nothing), `pgard doctor` shows a `[fail]` row, and the dashboard shows the same reason and will not remove anything from the keychain. The invalid value itself is never printed. `pgard doctor` shows which App is used, for example `[ok] GitHub App: built-in PGARD App (Iv23liKDf0mhnPl2c7zj)` or `[ok] GitHub App: <id> from PGARD_GITHUB_APP_CLIENT_ID (override)`. When an override is in use, `login`, `scan` and `project verify` also print `Using GitHub App <id> from PGARD_GITHUB_APP_CLIENT_ID (override).` Only where the client id comes from is configurable: owner approval, current access and contribution are checked the same way for every App.

`PGARD_GITHUB_APP_SLUG` is the optional slug of that App's page (`https://github.com/apps/<slug>`), used only for the install link of the [guided install](#first-run-sign-in-app-install-continue). The built-in App's slug is `pgard-jadenmeister`. A value must consist of lowercase letters, digits and `-` (up to 100 characters); anything else **blocks** exactly like a malformed client id, with the reason "PGARD_GITHUB_APP_SLUG is set but is not a valid GitHub App slug (lowercase letters, digits and "-"); fix or unset it.". When the client id is overridden without a slug, there is no install link. A malformed slug does not block `pgard logout` or the dashboard's **Sign out and remove from OS keychain**, because the keychain entry is named by the client id alone. Setting `PGARD_GITHUB_APP_SLUG` without `PGARD_GITHUB_APP_CLIENT_ID` (sign-in with the built-in App, install link to another App) prints a warning once in `scan`, `project verify` and the dashboard: installing that other App can never approve PGARD.

```sh
export PGARD_GITHUB_APP_SLUG=<slug of your own GitHub App>
```

When sign-in is needed, PGARD shows the URL `https://github.com/login/device` and a short user code, and opens the URL in your browser when stdout is a terminal (unless `--no-browser`). You open the URL, enter the code and approve. The token is never printed, logged, put in process arguments or environment variables, or written to a file.

#### Saved sign-in (OS keychain)

After a device-flow sign-in (from `pgard login`, a scan, `project verify` or the dashboard), PGARD saves it in the **OS keychain**: macOS Keychain, Windows Credential Manager or the Linux Secret Service. Later CLI runs (`scan`, `project verify`) and dashboard sessions reuse it, so you do not enter a code on every scan. Only the sign-in is reused: the owner-approval, access and contribution checks still run against GitHub before every scan. Run `pgard login` again to replace the saved sign-in, for example to switch accounts.

- The entry is keyed by GitHub host and App client id. The built-in App and an override with the same client id share one entry; an override with another client id never reuses the built-in App's token, or the other way round.
- If the App issues expiring tokens (8 hours, with a 6-month refresh token), PGARD refreshes the access token automatically. GitHub does not require a client secret to refresh tokens that came from the device flow, so PGARD has none.
- Before a saved token is used, PGARD checks it with GitHub (`GET /user`). If the entry is expired, malformed, revoked (GitHub answers 401) or cannot be refreshed, PGARD deletes the entry, says so, and runs the device flow again.
- If no keychain is available (for example a Linux server without a Secret Service), PGARD says why and keeps the sign-in in memory only, for the current CLI process or dashboard session, as before.
- `pgard logout` (or the dashboard's **Sign out and remove from OS keychain**) deletes the entry. It does **not** revoke the token at GitHub: PGARD cannot, because that needs the App's client secret. The token stays valid until it expires (or until it is revoked, if the App does not issue expiring tokens); revoke it at <https://github.com/settings/apps/authorizations> if needed.
- `pgard doctor` shows whether a sign-in is saved and for which account, never the token.
- On macOS the keychain item trusts the `node` binary, so any other Node.js script run by the same user can read it without a prompt.

GitHub App owners can turn token expiry on or off under the App's settings (**Optional features → User-to-server token expiration**). PGARD works either way: with expiry it refreshes, without it the saved token is used until it is revoked.

## Scan scopes and coverage

| Scope     | What it covers                                                        | Selected by                        |
| --------- | --------------------------------------------------------------------- | ---------------------------------- |
| `code`    | Current source code and configuration                                 | `scan`, `scan code`, `scan all`    |
| `history` | Committed `.env` files and secrets in tracked files and Git history   | `scan`, `scan history`, `scan all` |
| `web`     | Anonymous read-only HTTP checks of a confirmed service on `127.0.0.1` | `scan web`, `scan all`             |

Every result reports coverage for each area, so you can see what was and was not checked:

| Status         | Meaning                                                 |
| -------------- | ------------------------------------------------------- |
| `completed`    | The area ran to the end. Findings may or may not exist. |
| `partial`      | Only part of the area ran. A note says what is missing. |
| `not_tested`   | You selected the area, but it could not run.            |
| `not_selected` | You did not request the area.                           |

`scan all` (and `scan web`) report `partial` with exit code 4 when no web target is confirmed: when you choose **Continue without web checks**, or when there is no interactive terminal. Answering no to the confirmation question returns you to port selection. The `web` scope is then `not_tested`.

## Analyzers and rules

| Analyzer        | Scope     | Rule ids                                                                                                                                                                                            |
| --------------- | --------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Source analysis | `code`    | `PG-SQL-*`, `PG-XSS-*`, `PG-SSRF-*`, `PG-CMD-*`, `PG-PATH-*`, `PG-CRYPTO-*`, `PG-AUTH-*`, `PG-COOKIE-*`, `PG-CSRF-*`, `PG-BRUTE-*`                                                                  |
| Git history     | `history` | `PG-SECRET-001` (committed environment file), `PG-SECRET-002` (secret in a tracked file), `PG-SECRET-003` (secret only in history), `PG-HYGIENE-001` (dependency directory committed, a suggestion) |
| Local HTTP      | `web`     | `PG-WEB-001` to `PG-WEB-013`                                                                                                                                                                        |

Source analysis covers JavaScript, TypeScript, React (JSX/TSX), Vue and Go files. It walks the working tree and does not enter build output and caches (`dist/`, `build/`, `out/`, `.next/`, `coverage/` and similar) or dependency directories: `node_modules/` and `bower_components/` anywhere, and a `vendor/` only at the repository root or next to a `composer.json`, `go.mod` or `Gemfile` in the same directory (never under `src/`, `app/` or `lib/`, so a first-party `src/vendor/` module is analyzed). The skipped dependency directories are listed in the `source:dependency-directories` coverage note, for example `Skipped 2 dependency directories (third-party code, not analyzed): node_modules/, vendor/ (composer.json).` (up to 5 are named, fewer when the paths are long, and the rest are counted). A root `vendor/` with no manifest next to it is skipped as an assumption and labeled `vendor/ (repository root, no manifest; assumed third-party)`. Run `pgard rules list` (optionally with `--language`) for the current list of rules and their severities, instead of relying on a copy in this README.

For the HTML sinks (`innerHTML`, `outerHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`), a value passed straight through a sanitizer call (such as `DOMPurify.sanitize(...)`) is not reported. In JavaScript and TypeScript, a variable also counts as sanitized when PGARD resolves it (with TypeScript's symbol resolution, within the file) to its own `var`/`let`/`const` declaration and every assignment to it is a sanitizer call. Imports, parameters, globals, top-level `var`/`let` of a classic script, and any variable in a file that uses `eval`, `with`, `Function` or string timers are never treated as sanitized. Sanitizers are recognized by function name only; PGARD does not check how the sanitizer is configured.

## Code-based analysis

PGARD does not ship, download or query a vulnerability database, and it does not compare dependency versions with known advisories (CVE, OSV or similar). Findings are decided from the code itself: query statements, server code and configuration in the current files, secrets in the Git history, and the responses of the local HTTP service you confirm. Lockfiles are not checked for known vulnerable versions.

A scan in which every selected area completed reports `completed` and exits with code 0. Exit code 4 means that part of the selected coverage really is missing, for example an unconfirmed web target or a history scan that hit its limits.

## Local web checks

`scan web`, `scan all` and the dashboard check a web service only after you confirm it:

1. Authorization must pass before PGARD touches any port, in both the CLI and the dashboard (in the dashboard, port access also expires 30 minutes after the check; see [Dashboard](#dashboard)).
2. To show each service's identity, PGARD sends one `GET /` to each discovered listening port on `127.0.0.1` (after authorization passes). It lists the ports that answer HTTP. The list can be incomplete, so **Other port** is always offered. A port number alone says nothing about which project it belongs to.
3. It shows the service's URL, HTTP status, page title and guessed technology.
4. You answer `Is this the current project's service? [y/N]`. Only an explicit `y` confirms. `--port` still requires this confirmation.
5. Without an interactive terminal the target cannot be confirmed, so `web` is `not_tested` and the scan is `partial` (exit code 4).

The checks send only anonymous `GET`/`HEAD` requests to `127.0.0.1:<port>`. Redirects are followed only on the same loopback origin, and links that look like logout, delete or reset actions are skipped. Limits: 20 pages, depth 2, 5 seconds per request, 60 seconds in total and 1 MB per response body. They look at security headers, cookie flags, CORS with credentials, server version disclosure, directory listing, and whether `/.env` or `/.git` is served (presence only, values are never kept). A missing header is reported as informational, not as proof of a vulnerability.

A badly built application can still change state on a `GET` request. PGARD cannot guarantee that the checks have no side effects.

## Git history checks

`scan history` reads the files tracked at `HEAD` and the changes of the most recent 1,000 commits (all reachable commits, not only the first-parent line), within a 60-second budget. Blobs over 1 MiB, blobs skipped after 64 MiB of content has been read, and running out of time make the area `partial` with a note. Binary files are not scanned for secrets; the note says how many. Secret values are compared in memory only and are never included in findings or reports.

- `PG-SECRET-001`: a committed environment file (`.env`, `.env.local`, `prod.env`, ...; templates such as `.env.example` are excluded). Its values are never shown.
- `PG-SECRET-002`: a secret in a file tracked at `HEAD`.
- `PG-SECRET-003`: a secret that appears in history but no longer in the current files.
- `PG-HYGIENE-001` (info, shown as a suggestion): a dependency directory is tracked at `HEAD`. One finding per scan names each root directory with its tracked file count, listing up to 5 directories. The fix: remove it from the index without deleting your local copy (`git rm -r --cached node_modules`), add it to `.gitignore` and let the package manager restore it. It is decided from the tracked paths only; the working tree is not read. A root is the outermost flagged directory of a vendored path (see [Suggestions in third-party or vendored code](#suggestions-in-third-party-or-vendored-code)), so nested `node_modules/` count toward their root:
  - `node_modules/`, `bower_components/`, `jspm_packages/` and `Pods/` are always flagged.
  - `vendor/` is flagged only at the repository root or next to a tracked `composer.json`, `go.mod` or `Gemfile` in the same directory. It is not flagged for Go module vendoring (a tracked `vendor/modules.txt` next to a tracked `go.mod`), which is the workflow Go supports. A first-party `src/vendor/` module is never vendored, so it is never flagged.
  - Rails importmap pins are not flagged: when `config/importmap.rb` is tracked next to the `vendor/`, the files in `vendor/javascript/` are committed on purpose by `bin/importmap pin` and are not counted. The other subdirectories are then reported one by one, so a committed `vendor/bundle/` (installed gems) is still flagged as `vendor/bundle/` and the suggested `git rm` leaves the pins alone. Loose files directly in `vendor/` (`vendor/jquery.min.js`) still count toward `vendor/`, and the fix names them one by one (`git rm --cached vendor/jquery.min.js`, up to 5 and then a count) instead of the whole `vendor/`, and a dependency directory nested in the pins (`vendor/javascript/node_modules/`) is still flagged.
  - Placeholder files that only keep a directory in Git (`.keep`, `.gitkeep`, such as the `vendor/.keep` that `rails new` creates) are not counted.
  - `third_party/` is never flagged: it usually holds code copied in on purpose.
  - When an outer directory is not flagged (Go module `vendor/`, `third_party/`), a `node_modules/`, `bower_components/`, `jspm_packages/` or `Pods/` inside it still is, for example `vendor/node_modules/`. Findings inside unflagged directories are still vendored suggestions.

Secrets are private keys, well-known token formats (AWS, GitHub, Slack, Stripe, Google API keys), passwords in URLs (`postgres://user:password@host`) and generic credential assignments (`password = ...`, `api_key: ...`, `password := ...`, `headers["x-api-key"] = ...`, also with a type annotation or a quoted value behind a condition such as `cond ? "..." : ...`). A generic assignment counts only when its value is a literal that looks random enough and is not a placeholder. A password in a URL is reported unless it is a placeholder (`user:pass`, `${DB_PASSWORD}`, `$DB_PASSWORD`, or the user name repeated); a short or simple one is reported with low confidence. In source files, an unquoted value on a line that clearly looks like code (a type, a parameter list, a constant or variable name) is not treated as a credential. Lines inside string literals, including multi-line ones (template literals, `"""` blocks, heredocs, raw strings), are never treated as code; when the file cannot be read reliably (for example an unterminated string), the match is reported. Detection is pattern-based, so unusual forms can still be missed.

PGARD calls a secret or `.env` file "removed" only when it can show that the current files no longer hold it. Before that, it searches the current commit with `git grep -F` (the values are passed on stdin, never as arguments), which also covers files it did not read itself (too large, over the read budget, or binary). UTF-16 text files, which `git grep` cannot search, are decoded and searched in memory. When the current state cannot be established, for example because a file could not be read or the search did not finish, the finding says whether the value or file is still current **could not be checked**, instead of claiming it was removed.

## Results and reports

The terminal result shows a severity chart, the findings (confirmed, suspected or informational) with a `file:line` or URL, redacted evidence, guidance, and the coverage of each area.

### Findings in test or fixture code

Findings in test or fixture code are listed after the other findings, in their own group: **In test or fixture code (N)**. Their rule, severity and evidence are unchanged, but their confidence is capped at `low`. The headline count and the severity chart cover regular code only (for example `Findings by severity (3 total) - plus 2 in test or fixture code`). These findings are not dropped, because a real secret committed in a test is still exposed. The CLI, the dashboard and the HTML/PDF reports use the same grouping.

The classification is by path only, never by file content. A file is test or fixture code when:

- its name matches `*.test.*`, `*.spec.*` or `*_test.go`, or
- it is under a `__tests__/`, `__mocks__/`, `__fixtures__/`, `fixtures/` or `testdata/` directory, or
- it is under a `test/` or `tests/` directory, **unless** it is a configuration file: `.env*`, `.npmrc`, `Dockerfile*`, `settings.py`, `*_settings.py`, `config.py`, or a `.yml`, `.yaml`, `.tf`, `.tfvars`, `.properties`, `.ini`, `.toml`, `.json`, `.conf`, `.cfg` or `.xml` file. Such files may configure a real deployed test environment, so they count as regular code.

Directory names are matched case-insensitively. The rule applies to findings from every scope, so a `.env` under `fixtures/` is a test finding, while `deploy/test/.env` is not.

### Suggestions in third-party or vendored code

Findings in third-party dependency code committed to the repository are shown as suggestions, not as regular findings: you do not own that code and cannot fix it there. They are listed last, after the test or fixture group, in **Suggestions: in third-party/vendored code (N)**, with the note "This code is a committed dependency, not your code. Review it if it's unexpected; otherwise consider removing it from Git." Their rule, severity and evidence are unchanged, but their confidence is capped at `low`. The headline count and the severity chart do not include them (for example `Findings by severity (3 total) - plus 2 in test or fixture code, 5 suggestions in vendored code (1 high)`; critical and high suggestions are counted in the parentheses so they are not hidden in a total). They are never dropped, because a real secret committed in `node_modules/` is still exposed. Coverage, the overall status and exit codes do not change. The CLI, the dashboard (with the same filters) and the HTML/PDF reports use the same grouping, and the `PG-HYGIENE-001` suggestion (see [Git history checks](#git-history-checks)) is listed in the same group.

The classification is by path only, never by file content. A file is vendored when a directory in its path is:

- exactly `node_modules`, `bower_components`, `jspm_packages` or `Pods`, anywhere in the path, or
- exactly `vendor` or `third_party`, **unless** a directory before it is `src`, `app` or `lib` (in any letter case, so `Src/vendor/` is also your own code). Those names are also common first-party module names (`nest g module vendor` creates `src/vendor/`), so `src/vendor/vendor.service.ts`, `packages/web/src/third_party/a.ts` and `app/vendor/client.rb` are your own code.

Also:

- Whole directory names only. The vendored names are matched case-sensitively, because package managers create them exactly so and a lowercase `pods/` is often Kubernetes configuration: `src/vendored.ts`, `my_node_modules_x/index.js`, `Vendor/` and `k8s/pods/` are not vendored.
- Go and PHP (Composer) `vendor/` directories at the top of a project or package (`vendor/`, `api/vendor/`) are both dependency copies, so both count.
- Build output such as `dist/` or `build/` is your own output and is not vendored.
- A path that is both vendored and test code (`node_modules/pkg/test/a.js`) is vendored.

HTML and PDF reports are rendered from the same redacted result. The HTML report is a single file with no scripts and a strict CSP. Reports are written only to the directory you name, never overwrite existing files, and are created with mode `0600`. Keep reports outside the repository so they are not committed by mistake.

## Dashboard

`pgard dashboard` finds the Git root of the current directory, shows it and asks `Start the dashboard for this project? [y/N]`. It needs an interactive terminal; without one it exits with code 2. After you confirm, it starts the local web app and prints a private session URL:

```text
PGARD dashboard is running on 127.0.0.1 only.
Open this private session URL in your browser (valid until you stop the dashboard): http://127.0.0.1:<port>/#token=<random>
```

The dashboard runs its own scans (it never reads CLI results). It shows the authorization checks and the GitHub device code, lets you pick and confirm a local service, select scopes, follow progress, filter findings (test or fixture findings and suggestions in vendored code are shown in their own groups) and export HTML/PDF reports. It reuses the GitHub sign-in saved in the OS keychain on the server side; the token never reaches the browser. There are two sign-out buttons: **End dashboard session (keep keychain sign-in)** forgets the session in this dashboard only, and the next check reuses the keychain sign-in; **Sign out and remove from OS keychain** also deletes the saved sign-in (for the CLI too). If `pgard login` switches to another GitHub account while the dashboard runs, the dashboard drops its last check, so local service discovery and probes need a new check. Stop the dashboard with Ctrl+C: its GitHub session ends (the keychain sign-in is kept) and all results are discarded.

When a device code is needed, the dashboard shows an **Open the GitHub sign-in page** button and, unless `pgard dashboard --no-browser`, opens the page itself. When the authorization panel is blocked only because the PGARD GitHub App is not installed for this repository and you can approve (or GitHub cannot show your organization role yet; the CLI's wording is used), it shows an **Install the PGARD GitHub App** button (opens a new tab), checks owner approval again every 5 seconds for up to 10 minutes, and then runs the full check again automatically. The server enforces both limits: at most one re-check every 5 seconds, and only within 10 minutes of when the check finished, so reloading the panel does not extend the wait. Otherwise it shows the same `Ask an owner of <account> ...` link as the CLI.

Port discovery, identity probes and target confirmation are allowed only after the dashboard's latest authorization check for this project passed, and only for 30 minutes after that check finished. The dashboard shows when this window ends; after that (or if the system clock moves back), you must check again before it contacts local services. A new check or a sign-out closes the window at once and aborts probes that are still running, and the page drops port lists and probe results from an earlier check. Each scan runs the full authorization check again regardless of this window.

How the dashboard protects itself:

- It binds to `127.0.0.1` only, on a free port.
- A random 32-byte session token is passed in the URL **fragment**, so the browser never sends it in requests or `Referer` headers. The page removes it from the address bar and keeps it in memory. Do not share the URL.
- Every API call must carry the token in the `x-pgard-token` header. The `Host` header must be exactly `127.0.0.1:<port>` (DNS rebinding protection). Requests from another `Origin` and cross-site requests are refused, and no CORS headers are sent.
- Every response has `Cache-Control: no-store`, a strict Content-Security-Policy, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
- The browser cannot choose or read project files. The project root is fixed when the dashboard starts. The only path the browser supplies is an existing directory for report export: files are never overwritten there, and a directory inside the repository needs confirmation. The browser receives only redacted findings (with short redacted snippets), never full source files or the GitHub token.

## Privacy and network traffic

- Your code, Git history and scan results are processed on your computer and are not uploaded anywhere. Results are kept in memory and discarded when the process or dashboard stops; only reports you export are saved.
- The GitHub sign-in is saved in the OS keychain, never in a file, and never sent to the browser. Without a keychain it is kept in memory only. See [Saved sign-in](#saved-sign-in-os-keychain).
- The only external network traffic is to GitHub: the device-flow sign-in (and refreshing a saved sign-in) and GitHub API calls that read the metadata needed for authorization (your identity, the app installation, your organization membership (for organization repositories), your access and your contributions). To check contribution, PGARD sends the SHAs of local commits to GitHub (for the verified owner, only to check that local history shares a commit with the default branch). `pgard doctor` also checks whether `api.github.com` is reachable.
- After authorization passes, PGARD sends one `GET /` to each discovered listening port on `127.0.0.1` to show its identity. The web checks then send requests only to the service you confirmed.
- PGARD does not ship, download or query a vulnerability database.

## Out of scope for the MVP

- Direct database connections
- Docker or container configuration
- Performance and load testing
- Scanning remote (non-loopback) services
- Attack requests, form submission and other state-changing requests
- Logged-in (authenticated) web browsing (#45). The `web:authenticated` area is always `not_selected`, and PGARD never asks for application passwords.
- Dependency vulnerability (CVE/advisory) lookups: PGARD ships no vulnerability database.

## Known limitations

- [#44](https://github.com/JadenMeister/pgard/issues/44) PDF reports replace text outside Latin-1 (for example Korean) with `?`. Use the HTML report for the full text.
- [#45](https://github.com/JadenMeister/pgard/issues/45) Logged-in web browsing is not available: it is out of scope for the MVP (see [Out of scope for the MVP](#out-of-scope-for-the-mvp)).
- Contribution is checked conservatively for users who are not the verified owner: co-author trailers and unsigned direct pushes do not count, so a collaborator who only co-authored commits or pushed unsigned commits is blocked at contribution until a pull request of theirs is merged or they push signed commits.
- [#143](https://github.com/JadenMeister/pgard/issues/143) Follow-ups from the keychain sign-in review: narrow races between a keychain save and a removal; a session-only dashboard sign-out during a token refresh can make the next use ask for a new device code; and after `pgard login` switches accounts, the dashboard keeps the previous account's port access for up to 30 minutes (scans still re-check authorization).
- Detection is not complete. Missing findings do not mean the project is secure.
- Port discovery can be incomplete or unavailable. Type the port by hand in that case.

## Development

This is an npm workspaces monorepo written in TypeScript.

| Path                       | Contents                                            |
| -------------------------- | --------------------------------------------------- |
| `apps/cli`                 | The `pgard` command-line tool                       |
| `apps/local-web`           | The local web dashboard (server and React UI)       |
| `packages/policy`          | Authorization checks                                |
| `packages/github-auth`     | GitHub device flow, API client, OS keychain sign-in |
| `packages/scan-core`       | Scan orchestration, scopes and coverage             |
| `packages/source-analysis` | Source code rules                                   |
| `packages/git-history`     | Git history and secret scanning                     |
| `packages/http-local`      | Local HTTP checks and port discovery                |
| `packages/findings`        | Shared finding and coverage types, redaction        |
| `packages/report`          | HTML and PDF reports                                |
| `tests/integration`        | Cross-package integration tests                     |

```sh
npm ci
npm run build         # build all packages and the dashboard UI
npm run typecheck     # type-check only
npm test              # run the Vitest suite
npm run format        # format with Prettier
npm run format:check  # check formatting
npm run check         # typecheck + format:check + test
```

CI runs `npm ci`, `npm run build`, `npm run format:check` and `npm test` on pull requests and pushes to `main`.

### Design documents

PGARD was built from three Korean planning documents in [`docs/`](docs/):

- [`PGARD_AGENT_BRIEF_KO.md`](docs/PGARD_AGENT_BRIEF_KO.md): the implementation brief. It sets the product scope, the authorization gate, the scan boundaries and the definition of done.
- [`PGARD_CLI_AND_STRUCTURE_KO.md`](docs/PGARD_CLI_AND_STRUCTURE_KO.md): the command set and the layout of the apps and packages.
- [`PGARD_DEVELOPMENT_CONVENTIONS_KO.md`](docs/PGARD_DEVELOPMENT_CONVENTIONS_KO.md): the rules for commit units, messages, naming, verification and pull requests.

Where these documents and this README disagree, this README and the code are correct, because they reflect decisions made later.

## License

[MIT](LICENSE)
