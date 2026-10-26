# PGARD

[![CI](https://img.shields.io/github/actions/workflow/status/JadenMeister/pgard/ci.yml?branch=main&label=CI&logo=githubactions&logoColor=white)](https://github.com/JadenMeister/pgard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/github/license/JadenMeister/pgard?color=blue)](LICENSE)
[![Node.js](https://img.shields.io/badge/node-22.23.4%20%7C%2024.22.1%20%7C%2026.12.1-339933?logo=nodedotjs&logoColor=white)](#requirements)
[![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)](tsconfig.base.json)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey?logo=apple&logoColor=white)](#requirements)
[![Status: pre-release](https://img.shields.io/badge/status-pre--release-orange)](#known-limitations)
[![Data stays local](https://img.shields.io/badge/data-stays%20local-2ea44f)](#privacy-and-network-traffic)
[![Last commit](https://img.shields.io/github/last-commit/JadenMeister/pgard/main)](https://github.com/JadenMeister/pgard/commits/main)

English | [한국어](README.ko.md)

PGARD (`pgard`) is a local security scanner for GitHub projects you are authorized to scan. It runs on your own computer as a command-line tool and a local web dashboard. It checks the current code and configuration, the Git history, and (optionally) a web service you run on `127.0.0.1`. Findings are decided from the code itself; scans do not download or query a vulnerability database (see [Code-based analysis](#code-based-analysis)). An optional, user-run command downloads public OSV data for later dependency checks (see [Privacy and network traffic](#privacy-and-network-traffic)).

Before every scan, PGARD checks that the repository owner approved PGARD, that you currently have access to the repository, and that you own it or really contributed to it. Your code and the results stay on your computer.

PGARD is a pre-release under active development. The first release (v0.1.0) is planned. PGARD does not find every vulnerability, and "no findings" never means "secure".

> **Current status:** PGARD ships the client id of the PGARD GitHub App, so signing in needs no setup. A scan still needs the App installed on the account that owns the repository: your personal account, or an organization you own (see [Authorization model](#authorization-model)).

PGARD is released under the [MIT License](LICENSE).

## Contents

- [Policies](#policies)
- [Requirements](#requirements)
- [Install and build](#install-and-build)
- [Commands](#commands)
- [Authorization model](#authorization-model)
- [Scan scopes and coverage](#scan-scopes-and-coverage)
- [Analyzers and rules](#analyzers-and-rules)
- [Code-based analysis](#code-based-analysis)
- [Local web checks](#local-web-checks)
- [Git history checks](#git-history-checks)
- [Project configuration](#project-configuration)
- [Results and reports](#results-and-reports)
- [Dashboard](#dashboard)
- [Privacy and network traffic](#privacy-and-network-traffic)
- [Out of scope](#out-of-scope)
- [Accuracy](#accuracy)
- [Known limitations](#known-limitations)
- [Development](#development)
- [License](#license)

## Policies

These are the rules PGARD follows. Each entry says what the policy is and links to where it is written down in full. This README and [`docs/RESULT_SCHEMA.md`](docs/RESULT_SCHEMA.md) describe current behaviour. The planning documents in [`docs/`](docs/README.md) (Korean originals with English translations) are the MVP planning record: where they differ (for example, they rule out an advisory database; PGARD now has a user-run download of public OSV data, but does not yet match dependencies against it), this README wins.

- **Authorization gate.** Five checks (repository, GitHub identity, owner approval, current access, contribution) run again on every scan. There is no option to skip them or to reuse an earlier result, and if evidence is missing or unclear the scan is blocked (exit code 3). See [Authorization model](#authorization-model).
- **Organization repositories.** Only an active owner of the organization can scan an organization repository, and the PGARD GitHub App must be installed on the organization with access to the repository. See [Organization repositories](#organization-repositories).
- **Local processing and network traffic.** Code, Git history and results are processed on your computer and never uploaded. Scans contact GitHub only, for sign-in and authorization metadata. The one other destination is the OSV export host, and only when you run `pgard advisories update` yourself: it downloads public data and uploads nothing. See [Privacy and network traffic](#privacy-and-network-traffic).
- **Credentials.** The GitHub token is saved only in the OS keychain, or kept in memory when no keychain exists. It is never written to a file, printed, logged or sent to the browser. `pgard logout` removes the saved sign-in (it does not revoke the token at GitHub). See [Saved sign-in](#saved-sign-in-os-keychain).
- **Redaction.** Secret values that PGARD recognises are replaced by their kind in terminal output, findings, HTML/PDF reports and the dashboard. What counts as a secret is defined in [Git history checks](#git-history-checks); see also [Results and reports](#results-and-reports). Detection is pattern-based, so unusual forms can be missed.
- **Local web dashboard security.** It listens on `127.0.0.1` only, requires a per-session token, checks the `Host` and `Origin` headers, sends a strict Content-Security-Policy and serves reports as browser downloads without writing files. See [How the dashboard protects itself](#how-the-dashboard-protects-itself).
- **Web checks.** Checks send only anonymous `GET`/`HEAD` requests to `127.0.0.1`, and only to the service you confirm (after authorization, one identity `GET /` goes to each discovered local port). PGARD sends no POST/PUT/DELETE requests or form submissions, but a badly built app can still change state on a `GET`. See [Local web checks](#local-web-checks).
- **Result schema versioning.** The scan result carries a `major.minor` `schemaVersion`; readers refuse another major version. See [`docs/RESULT_SCHEMA.md`](docs/RESULT_SCHEMA.md).
- **Stored results.** `pgard scan` keeps the redacted result locally (last 20 scans per repository, 90 days, owner-only permissions on macOS and Linux, never uploaded). The authorization gate is never cached: it runs again on every scan. The stored result does include what a result contains, among it the authorization reasons (GitHub login, organization names and roles), so treat the folder as private. Opt out with `--no-store` or `PGARD_NO_STORE=1`; delete with `pgard history clear --all`. Dashboard scans are not stored. See [Stored results](#stored-results).
- **Out of scope.** Remote services, attack or state-changing requests, logged-in web browsing, matching dependencies against vulnerability data and more are not supported yet. See [Out of scope](#out-of-scope).
- **Development conventions.** Commit units and messages, branch and pull request boundaries, and the issue, project board and review-before-merge workflow are described in [`PGARD_DEVELOPMENT_CONVENTIONS_EN.md`](docs/PGARD_DEVELOPMENT_CONVENTIONS_EN.md). See also [Development](#development).

## Requirements

- Node.js 22.23.4, 24.22.1 or 26.12.1, or a newer patch on the same line. These are the releases that fix the vulnerabilities in the [Node.js security release of 21 October 2026](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases), including a Brotli decoder out-of-bounds write that can lead to remote code execution (CVE-2026-111497) and TLS hostname check bypasses. PGARD uses `fetch` and TLS to call the GitHub API, so older releases are not supported: `pgard doctor` fails the Node.js check on them. Node.js 20 and earlier and the odd-numbered lines get no fixes. Check your version with `node --version`.
- Git
- macOS, Linux or Windows. CI runs the full test suite on all three. Local port discovery uses `lsof` on macOS (falling back to `netstat`), `/proc/net/tcp*` on Linux and `%SystemRoot%\System32\netstat.exe` on Windows. You can always type a port by hand.
- Windows notes: the sign-in is kept in Windows Credential Manager, the browser opens through `explorer.exe`, and reports cannot be created with mode `0600` because Windows has no such mode. A report there gets the default permissions of the folder you choose, so pick a folder only you can read. Terminal output: `NO_COLOR` turns off colour only. `TERM=dumb` turns off colour and, on non-Windows systems, also gives ASCII text. On Windows, text is ASCII unless the host is Windows Terminal, VS Code or a similar terminal; colour stays on there regardless of the host.
- A GitHub account (see [GitHub App and sign-in](#github-app-and-sign-in))

## Install and build

### Install from npm or Homebrew (from the first release)

The first release (planned v0.1.0) is not published yet. Until then the npm name `pgard` is reserved by a placeholder package (0.0.1) that has no CLI: `npm install -g pgard` installs only that placeholder, and you get no `pgard` command. Install from source (below) until the release. After the first release:

```sh
npm install -g pgard   # installs the `pgard` command
npx pgard doctor       # or run it once without installing
brew install jadenmeister/pgard/pgard   # Homebrew (macOS and Linux), after the first release
```

The package is `pgard` and its command is `pgard`. Versions and the release process are described in [docs/RELEASING.md](docs/RELEASING.md); changes are listed in [CHANGELOG.md](CHANGELOG.md).

### Build from source

Build it from source:

```sh
git clone https://github.com/JadenMeister/pgard.git
cd pgard
npm ci
npm run build          # TypeScript packages and the dashboard UI (Vite)
npm link -w @pgard/cli # optional: puts `pgard` on your PATH
```

Without `npm link`, run `node apps/cli/dist/bin/pgard.js <command>` from the repository.

### Build the package locally

The release artifact is one npm package, `pgard`, which bundles the CLI, the dashboard, the PDF font and the tree-sitter grammars. It is not published yet. To build it and check that it works when installed:

```sh
npm run pack:pgard   # builds and writes .pack/pgard-<version>.tgz (gitignored)
npm run smoke:pack   # installs that tarball into a temporary directory and runs it
```

`smoke:pack` runs `pgard --version`, `--help`, `rules list` and `doctor`, renders a Korean PDF with the embedded font (a fallback font fails the check), loads a grammar and starts the dashboard server. CI runs the same steps on Linux, macOS and Windows.

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
  pgard rules list [--language js|ts|react|vue|go] [--lang en|ko]
                                supported rules and unsupported areas
  pgard history clear --all | --repo owner/name
                                delete stored scan results (all, or one repository)
  pgard baseline set [--from-current] | show | clear
                                keep a scan as this repository's baseline; later
                                scans list matching findings under "In baseline"
  pgard doctor                  diagnose the environment (not an authorization)
  pgard advisories update       download public OSV vulnerability data (npm, Go)
                                to this computer; the only non-GitHub download
  pgard login                   sign in to GitHub once and save it in the OS keychain
  pgard logout                  remove the saved GitHub sign-in from the OS keychain
  pgard --help | <command> --help
  pgard --version
```

| Command                   | What it does                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `pgard`                   | Interactive menu: verify, scans, dashboard, rules, doctor, quit.                                                                                                                                                                                                                                                                                                                                                                                                               |
| `pgard project verify`    | Runs the authorization checks and shows each one (repository, GitHub identity, owner approval, current access, contribution) as passed, failed or unverifiable, with a reason. The result is not stored.                                                                                                                                                                                                                                                                       |
| `pgard scan`              | `code` + `history`.                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| `pgard scan code`         | Current source code and configuration.                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `pgard scan history`      | Committed `.env` files and secrets in tracked files and Git history.                                                                                                                                                                                                                                                                                                                                                                                                           |
| `pgard scan web`          | Anonymous, read-only checks of a local HTTP service on `127.0.0.1` that you confirm.                                                                                                                                                                                                                                                                                                                                                                                           |
| `pgard scan all`          | `code` + `history` + `web`. If no web target is confirmed, the result is `partial`.                                                                                                                                                                                                                                                                                                                                                                                            |
| `pgard dashboard`         | Starts the local web dashboard. See [Dashboard](#dashboard).                                                                                                                                                                                                                                                                                                                                                                                                                   |
| `pgard rules list`        | Lists the rule catalog grouped by scope (code, Git history, local HTTP; a rule with an unknown scope goes under "Other rules") with each rule's severity and languages, the detection criteria version, and the areas PGARD does not cover (including dependency vulnerability lookups, since PGARD ships no vulnerability database). Works outside a project and makes no network requests.                                                                                   |
| `pgard doctor`            | Checks Node.js, Git, GitHub reachability, local port discovery, which GitHub App PGARD signs in with (the built-in PGARD App, or `PGARD_GITHUB_APP_CLIENT_ID` as an override), and whether a GitHub sign-in is saved in the OS keychain (and for which account; never the token), and the age of the downloaded advisory data (none, a date, or stale after 7 days; read from local files, no network). It is a diagnosis only, not an authorization. Works outside a project. |
| `pgard advisories update` | User-run download of the public OSV bulk exports for npm and Go from `osv-vulnerabilities.storage.googleapis.com` (https only, that host only). Nothing is uploaded and no package names are sent. The archive is verified (zip structure, per-record checksums, size and time limits) and a compact index replaces the old data atomically; on any failure the old data stays. Never runs during a scan or from `doctor`. Exit code 4 if an ecosystem failed.                 |
| `pgard login`             | Signs in to GitHub with the device flow and saves the sign-in in the OS keychain, so later scans and the dashboard reuse it. Running it again replaces the saved sign-in. See [Saved sign-in](#saved-sign-in-os-keychain).                                                                                                                                                                                                                                                     |
| `pgard logout`            | Removes the saved GitHub sign-in from the OS keychain. See [Saved sign-in](#saved-sign-in-os-keychain).                                                                                                                                                                                                                                                                                                                                                                        |
| `pgard baseline`          | `set` keeps the newest stored scan of this repository as its baseline (`--from-current`: scan now and keep that scan), `show` describes it, `clear` deletes it. Later scans list findings in the baseline apart and highlight new ones; nothing is hidden and the exit code does not change. See [Baseline](#baseline).                                                                                                                                                        |
| `pgard history clear`     | Deletes the scan results that `pgard scan` stored on this computer, and the baselines. One option is required: `--all` deletes all of them, `--repo owner/name` those of one repository. Nothing is uploaded and no sign-in is needed. See [Stored results](#stored-results).                                                                                                                                                                                                  |

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
  --all-findings           list every finding and location; by default more than
                           5 findings in test, fixture or vendored code are
                           summarized, and groups show up to 3 locations
  --lang en|ko             language of the result screen, progress lines and rule
                           texts (default: PGARD_LANG, then the system locale,
                           then en). JSON and SARIF output are always English
  --report-lang en|ko      language of saved reports (default: the
                           --lang language)
  --format text|json|sarif json prints only the redacted result (schema in
                           docs/RESULT_SCHEMA.md) to stdout; sarif prints the
                           same result as SARIF 2.1.0 (for GitHub code
                           scanning; PGARD uploads nothing). Progress and
                           messages go to stderr. With web checks it needs --port
                           (prompts go to stderr). Exit codes are unchanged
  --no-browser             do not open GitHub pages (device sign-in, App
                           install) in the browser; the links are printed.
                           In a terminal, PGARD asks you to press Enter
                           before opening a page

If owner approval is the only failed check and the PGARD GitHub App just needs to
be installed, PGARD prints the install page link (in a terminal it opens after you press Enter), waits for it, re-runs the full
authorization and continues the scan.
```

### Options

- `--port N` (`scan web` and `scan all` only): the local service port, an integer from 1 to 65535. You still have to confirm the service.
- `--target-port N` (`dashboard` only): pre-selects the local service to check. You still confirm it in the browser. The dashboard itself runs on its own free port.
- `--report html|pdf|both` and `--output-dir <dir>` (any `scan`): save a report. The two options must be used together. The directory must already exist, and existing files are never overwritten. A directory inside the Git repository needs an explicit `y` (without an interactive terminal it is refused). By default, results are only shown in the terminal.
- `--all-findings` (any `scan`): list every finding and every location, each with its own evidence, and never collapse anything. This includes suppressed findings and findings in the baseline (see [Suppressions](#suppressions) and [Baseline](#baseline)). By default, groups show up to 3 locations (the evidence is shown once when all members share it, otherwise it says it varies), and when more than 5 findings come from test, fixture or vendored code the lower-severity ones are replaced by a summary (see [Grouping and collapsing](#grouping-and-collapsing)).
- `--format text|json|sarif` (any `scan`, default `text`): `sarif` prints SARIF 2.1.0 instead (see [SARIF output](#sarif-output)); it follows the same rules as `json` for stdout, stderr, `--port` and exit codes. `json` prints only the redacted scan result to stdout, exactly as described in [docs/RESULT_SCHEMA.md](docs/RESULT_SCHEMA.md) and readable with `readScanResult`. Progress, notices and prompts go to stderr, so `pgard scan code --format json > result.json` is valid JSON. Prompts never use stdout: `scan web` and `scan all` need `--port` (without it the command exits with the usage error 2 before scanning). The exit codes do not change. `--all-findings` has no effect on JSON, which always contains every finding. Prompts that are still possible (the `--port` confirmation, the GitHub App install guide, saving a report inside the repository) are shown on stderr when stdin and stderr are terminals, even if stdout is redirected to a file. Stdout holds exactly one document, the final result, which is also a blocked result when authorization failed. Stdout stays empty only for a usage error (exit 2), a cancellation, a directory that is not a repository (exit 3) and an internal error.
- `--lang en|ko` (any `scan`, `rules list`): language of the rule texts (titles, impact, fix) in the terminal. See [Language of rule texts](#language-of-rule-texts).
- `--report-lang en|ko` (any `scan`, with `--report`): language of the saved HTML and PDF reports (the whole report, not only the rule texts); defaults to the `--lang` language.
- `--language js|ts|react|vue|go` (`rules list` only): filter the rule list by language. Rules for any language are always included; `react` and `vue` also include the JavaScript/TypeScript rules.
- `--no-browser` (`scan`, `project verify`, `login`, `dashboard`): do not open GitHub pages (the device sign-in page, the App install page) in the browser; the links are only printed. Without it, in a terminal (stdin and stdout) PGARD prints the link and asks `Press Enter to open github.com in your browser...`; the page opens only after you press Enter (other keys are ignored). Waiting for sign-in or installation never depends on that prompt, and it is dropped as soon as the wait ends. Outside a terminal nothing is opened and nothing is asked. The links are always printed too, and a browser that fails to open is not an error.
- `--no-store` (`scan` only), or the environment variable `PGARD_NO_STORE=1`: do not keep this scan's result on this computer. Only the exact value `1` counts. Nothing is created in that case, not even the notice, and a [baseline](#baseline) is neither read nor applied. See [Stored results](#stored-results).
- `--all` or `--repo owner/name` (`history clear` only, exactly one of them): delete the stored results of every repository, or of one repository. `--repo` matches the `owner/name` stored inside the results, ignoring case, and works offline. After a repository was renamed or transferred, results stored earlier still carry the old name, so give that name (or use `--all`).
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

1. **Sign in.** PGARD prints the code and the link `https://github.com/login/device`, and in a terminal opens it in your browser after you press Enter (see `--no-browser`). You enter the code and authorize the PGARD GitHub App.
2. **Install the App, if that is all that is missing.** When owner approval is the only failed check, and it failed only because the PGARD GitHub App is not installed on the owner account or its installation does not include this repository, and you may be the one who can approve (for a personal repository you are the owner; for an organization GitHub shows you as an active owner, or cannot show your role yet), PGARD prints the App's install page (and, in a terminal, opens it after you press Enter), preselected for the owner account and this repository:

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
- **Private repositories outside the App installation.** The PGARD GitHub App's sign-in token can only see private repositories that its installation includes. For any other private repository GitHub answers 404, so current access stays `failed` with "GitHub returned no access to github.com/<owner>/<repo>. For a private repository this usually means the PGARD GitHub App is not installed for it, or your account has no access." PGARD cannot tell which of the two is the case (or that the repository does not exist), so nothing passes. It then looks up the owner's account id (`GET /users/<owner>`, public) and your App installations, and offers one of two pages. If the App is **already installed** on the owner account (usually with selected repositories), PGARD opens that installation's settings page (`https://github.com/settings/installations/<id>`, or `https://github.com/organizations/<org>/settings/installations/<id>`) and tells you to add the repository under **Repository access → Only select repositories** and click **Save**; you do not install the App again. If it is **not installed**, PGARD offers the install page, preselected for the owner account only (the repository id is not known). That page pre-selects **All repositories**; choose **Only select repositories** and pick the repository to limit PGARD to it. Either way PGARD then waits and runs all five checks again from scratch. If the lookup or the installation listing fails, only the reason is shown (PGARD does not guess a page). For an organization your role cannot be verified before the change, so the guidance is shown as for an unreadable membership; for someone else's personal account PGARD asks you to have the owner do it. Afterwards the full check decides.
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

When sign-in is needed, PGARD shows the URL `https://github.com/login/device` and a short user code, and in a terminal (unless `--no-browser`) opens the URL in your browser after you press Enter. You open the URL, enter the code and approve. The token is never printed, logged, put in process arguments or environment variables, or written to a file.

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

PGARD does not ship a vulnerability database, a scan never downloads or queries one, and it does not yet compare dependency versions with known advisories (CVE, OSV or similar). Findings are decided from the code itself: query statements, server code and configuration in the current files, secrets in the Git history, and the responses of the local HTTP service you confirm. Lockfiles are not yet checked for known vulnerable versions.

Groundwork for that check exists: PGARD can read the exact resolved versions from `package-lock.json` / `npm-shrinkwrap.json` (v1 to v3), `pnpm-lock.yaml`, `yarn.lock` (classic and berry) and `go.mod` / `go.sum` without running any package manager or build tool (files are only parsed, never executed; symbolic links, oversized files and `node_modules` / build directories are skipped), and `pgard advisories update` downloads the public OSV data. Lockfiles of other ecosystems, unreadable or malformed lockfiles, and `package.json` files with no lockfile are listed as not covered, never as "no vulnerable dependencies". Matching and results come in a follow-up.

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
- `PG-SECRET-003`: a secret found in Git history (the evidence says whether it is still in the current files).
- `PG-HYGIENE-001` (info, shown as a suggestion): a dependency directory is tracked at `HEAD`. One finding per scan names each root directory with its tracked file count, listing up to 5 directories. The fix: remove it from the index without deleting your local copy (`git rm -r --cached node_modules`), add it to `.gitignore` and let the package manager restore it. It is decided from the tracked paths only; the working tree is not read. A root is the outermost flagged directory of a vendored path (see [Suggestions in third-party or vendored code](#suggestions-in-third-party-or-vendored-code)), so nested `node_modules/` count toward their root:
  - `node_modules/`, `bower_components/`, `jspm_packages/` and `Pods/` are always flagged.
  - `vendor/` is flagged only at the repository root or next to a tracked `composer.json`, `go.mod` or `Gemfile` in the same directory. It is not flagged for Go module vendoring (a tracked `vendor/modules.txt` next to a tracked `go.mod`), which is the workflow Go supports. A first-party `src/vendor/` module is never vendored, so it is never flagged.
  - Rails importmap pins are not flagged: when `config/importmap.rb` is tracked next to the `vendor/`, the files in `vendor/javascript/` are committed on purpose by `bin/importmap pin` and are not counted. The other subdirectories are then reported one by one, so a committed `vendor/bundle/` (installed gems) is still flagged as `vendor/bundle/` and the suggested `git rm` leaves the pins alone. Loose files directly in `vendor/` (`vendor/jquery.min.js`) still count toward `vendor/`, and the fix names them one by one (`git rm --cached vendor/jquery.min.js`, up to 5 and then a count) instead of the whole `vendor/`, and a dependency directory nested in the pins (`vendor/javascript/node_modules/`) is still flagged.
  - Placeholder files that only keep a directory in Git (`.keep`, `.gitkeep`, such as the `vendor/.keep` that `rails new` creates) are not counted.
  - `third_party/` is never flagged: it usually holds code copied in on purpose.
  - When an outer directory is not flagged (Go module `vendor/`, `third_party/`), a `node_modules/`, `bower_components/`, `jspm_packages/` or `Pods/` inside it still is, for example `vendor/node_modules/`. Findings inside unflagged directories are still vendored suggestions.

Secrets are private keys, well-known token formats (AWS, GitHub, Slack, Stripe, Google API keys), passwords in URLs (`postgres://user:password@host`) and generic credential assignments (`password = ...`, `api_key: ...`, `password := ...`, `headers["x-api-key"] = ...`, also with a type annotation or a quoted value behind a condition such as `cond ? "..." : ...`). A generic assignment counts only when its value is a literal that looks random enough and is not a placeholder. A password in a URL is reported unless it is a placeholder (`user:pass`, `${DB_PASSWORD}`, `$DB_PASSWORD`, or the user name repeated); a short or simple one is reported with low confidence. In source files, an unquoted value on a line that clearly looks like code (a type, a parameter list, a constant or variable name) is not treated as a credential. Lines inside string literals, including multi-line ones (template literals, `"""` blocks, heredocs, raw strings), are never treated as code; when the file cannot be read reliably (for example an unterminated string), the match is reported. Detection is pattern-based, so unusual forms can still be missed.

PGARD calls a secret or `.env` file "removed" only when it can show that the current files no longer hold it. Before that, it searches the current commit with `git grep -F` (the values are passed on stdin, never as arguments), which also covers files it did not read itself (too large, over the read budget, or binary). UTF-16 text files, which `git grep` cannot search, are decoded and searched in memory. When the current state cannot be established, for example because a file could not be read or the search did not finish, the finding says whether the value or file is still current **could not be checked**, instead of claiming it was removed.

## Project configuration

A project can keep an optional `pgard.config.json` at the Git root. It sets exclusions and test directories and holds a suppression list. It is **never** a way to change what PGARD is allowed to do: authorization, hosts, ports, network targets and rule severities cannot be configured, and any key not listed below is rejected. The file is part of the scanned repository, so PGARD treats it as untrusted data: it is read read-only, never executed, never followed through a symbolic link, and limited to 64 KiB. Where the operating system has `O_NOFOLLOW` (macOS, Linux) a link swapped in while the file is being opened is refused by the open itself; on Windows, which has no such flag, the opened file must be the very file that was inspected (same device and file id), or the config is refused. Only the config at the Git root is read: a `pgard.config.json` in a subdirectory is ignored. PGARD reads the file in the working tree, even if it is untracked or edited, and does not consult `HEAD`.

```json
{
  "version": 1,
  "exclude": ["legacy/**", "*.generated.ts"],
  "testDirectories": ["e2e", "tools/samples"],
  "suppressions": [
    {
      "ruleId": "PG-SQL-001",
      "path": "scripts/**",
      "reason": "Admin-only script; the input is not user controlled",
      "expires": "2027-01-31"
    }
  ]
}
```

- `version` (required): the number `1`.
- `exclude` (up to 200 patterns): source files left out of the source analysis.
- `testDirectories` (up to 100 patterns): paths classified as test code (see [Findings in test or fixture code](#findings-in-test-or-fixture-code)). They can only **add** the test context; a path that is test code by the built-in rules stays test code, and vendored code stays vendored. They apply to source code findings, not to Git history.
- `suppressions` (up to 200 entries): `ruleId` (for example `PG-SQL-001`), `path` (a pattern), `reason` (required, at most 300 characters) and an optional `expires` date (`YYYY-MM-DD`). They are applied: a matched finding stays in the result and is listed under `Suppressed (N)`; see [Suppressions](#suppressions) for matching, expiry, critical findings and the warnings. The coverage note counts them.

Patterns are repository-relative paths with `/` as the separator, case-sensitive: `*` matches within one path segment, `?` one character, `**` any number of segments. A pattern without `/` matches at any depth (`*.generated.ts`), and a pattern also matches everything below a matching directory (`legacy` and `legacy/**` are the same). Absolute paths, `..`, backslashes, `[ ] { }`, a leading `!`, more than 10 `*` in one segment and invisible characters (control and C1 control characters, line and paragraph separators, bidirectional, zero-width and other format characters, the combining grapheme joiner, Hangul filler characters, lone surrogates) are rejected, in patterns and in every other string of the file. Matching never builds a regular expression from a pattern, so there is no exponential blow-up. The work for one pattern and one path is at most pattern length times path length (a table is filled, nothing backtracks), with patterns capped at 200 characters and paths at 4,096. Those limits bound a single match, not the total, so a scan also has a hard work budget of 500 million table cells for all matches together. In measurements, 200 deliberately hostile patterns (`*?a?a...?a*` variants that defeat the star cap and the prefilter) took about 19 seconds without the budget for 10,000 typical paths and about 43 seconds for 10,000 255-character names; with the budget they stop after about 1 second (typical paths) and 0.3 seconds (long names), and a 4,000-character-path case stops in about 0.25 seconds. Ordinary patterns use a tiny fraction of the budget. When the budget runs out, the files after that point are **not** excluded and not reclassified (they are scanned as if no pattern applied), and the `source:config` coverage area becomes `partial` with a `WARNING` (exit code 4): simplify the patterns. Matching is case-sensitive and does no Unicode normalization, so `src/**` does not exclude `Src/x.js`. That direction is fail-safe: more is scanned, never less.

The validator is strict: exact keys and types, length and count limits, and unknown or duplicate keys are rejected.

**Nothing is excluded silently.** The source scan lists the excluded files in the `source:config-excluded` coverage area (also in the JSON result): the number of files, the number of source files found, the patterns (quoted, up to 5 and then a count) and a short hash of the pattern set and of the excluded file set, so a later `pgard scan` comparison notices a changed exclusion. The terminal result shows a prominent line above the findings, for example `! 12 files excluded by pgard.config.json (of 140 source files; 2 patterns, set 3fa91c2e5b7d4a60).`. A newly excluded file is never reported as "no longer reported" in a comparison with an earlier scan. A pattern that matches every file (`**`) or exclusions that leave nothing to analyze add a `WARNING` and make the area `partial` (exit code 4).

**`testDirectories` cannot demote findings quietly either.** Findings in test code are listed apart with their confidence capped at `low`, so a config that calls your production code "test" would make real findings look minor. Whenever the setting moved any finding into the test group, the terminal, the HTML and PDF reports and the dashboard show a prominent notice above the findings (`! 3 findings were classified as test code by the testDirectories setting of pgard.config.json`), and the test group's note says how many of its findings were classified by the config rather than by the built-in rules. The `source:config-test` coverage area counts the production files (files the built-in rules do not already treat as test or vendored code) that the patterns demote; when they match every such file, or at least half of them and more than 20, the area is `partial` with a `WARNING` (exit code 4). A real project keeps most of its code outside test paths, so that share is a sign of a mistaken or hostile pattern such as `*.*` or `src`.

**Git history is never excluded.** `exclude` applies to the source analysis only. Secrets in Git history and in tracked files are always scanned in full: a secret that was committed stays exposed in every clone whatever the file is called now, and paths in old commits do not map onto the current tree. The `history:config-excluded` coverage note says that the patterns were not applied to history.

**An invalid file never hides findings.** If `pgard.config.json` is not valid (unknown key, duplicate key, too large, a symbolic link, and so on), the scan still runs, as if there were no config at all: nothing is excluded, not even the valid parts. The `source:config` coverage area becomes `partial` with the first problems, the terminal shows a prominent line, and the exit code is 4. Fix the file, or delete it, to get `completed`.

## Results and reports

The terminal result shows a severity chart, the findings (confirmed, suspected or informational) with a `file:line` or URL, redacted evidence, guidance, and the coverage of each area.

### The terminal result screen

`pgard scan` prints, from top to bottom:

1. **Status line** with the repository, revision and scopes, then the `!` notices about `pgard.config.json`, suppressions and the baseline.
2. **Summary**: the areas requested and how many are completed, partial or not tested (a partial configuration file counts too); how many rules ran (from `ruleStats`; a rule that ran in a partially scanned area is counted separately); "Max per rule" (files, commits, pages: the largest count any rule examined, not a sum and not the size of the repository); the elapsed time; and, when an earlier scan of the repository is stored, **Since last scan: `+N new / -N no longer reported`**. It says "no longer reported", not "fixed", because the code may also have been skipped, renamed or removed; areas that could not be compared are named. A longer line with the same data follows the result. A row is left out when the result has no data for it (results of PGARD 1.0 have no `ruleStats`).
3. **Charts** of the findings by severity, by OWASP Top 10 2025 category (a finding counts once per category it maps to; findings without a mapping are counted apart) and by area (code, history, web). With colour on, bars use block characters in the severity colours; with `NO_COLOR`, a non-TTY output or `TERM=dumb` they are plain `#` bars; below 60 columns there are no bars, only `label  count` lines. Bars scale to the terminal width (`COLUMNS` when the output is not a terminal; 80 otherwise) and labels are cut to fit.
4. **Findings**, worst first, each with its location, redacted evidence, the fix, and the official standards of the rule (OWASP, CWE, CERT ids with their links; https only). Test, fixture and vendored findings follow in their own groups; when there are more than 5, the lower-severity ones are replaced by a count (see [Grouping and collapsing](#grouping-and-collapsing)).
5. **Coverage** per area and the **standards coverage** map.

The standards map uses four states and nothing else: `rules ran`, `rules partial`, `not run`, `no rules`. They say whether PGARD rules that map to the entry ran in this scan. None of them means "safe" or "covered", and nothing in the map is green.

### Standards coverage and rule statistics

The result says which rules ran and which standards entries those rules map to. Both are in the JSON result (`ruleStats`, `standardsCoverage`, schema 1.1) and a compact summary closes the terminal result. This is an example from a small TypeScript project with one Java file (code and history scopes; the output is cut to the first 200 characters of each line here):

```
Standards coverage (OWASP Top 10 2025)
  [rules partial] A01 Broken Access Control - 9 of 40 mapped CWEs have rules (PG-COOKIE-001, PG-CSRF-001, PG-PATH-001, PG-SECRET-001 +2); web rules not run: scope not selected; no completed mapped rule covers java (1 file) ...
  [rules ran] A03 Software Supply Chain Failures - 1 of 6 mapped CWEs have rules (PG-HYGIENE-001)
  [rules partial] A05 Injection - 3 of 37 mapped CWEs have rules (PG-CMD-001, PG-SQL-001, PG-SQL-002, PG-XSS-001 +1); no completed mapped rule covers java (1 file) ...
  [no rules] A08 Software or Data Integrity Failures - no rules
  CWE Top 25 2025: 0 rules ran, 6 rules partial, 0 not run, 19 no rules
```

**What the states mean.** None of them says the project is safe, and none says the category is covered. They say whether PGARD rules that map to the entry ran in this scan, and the line shows how few of the category's CWEs have a rule at all (`1 of 6 mapped CWEs have rules`). Nothing is shown in green.

- **Rule statistics** (`ruleStats`): one entry for each rule that ran in an area (a rule that runs in several languages has one entry per area): its area, the area's status, the number of targets it examined and the number of findings it reported there. Targets are counted by the analyzers, not estimated: the files a language analyzer actually ran on (files that were binary, over the size limit or skipped for the time budget are not counted), the commits and the history blobs read as text for the history rules, and the pages and responses for the web rules. A count that cannot be measured is `null` with a `reason`, never a guess. A rule of an area that was not selected or could not run has no entry. The same finding can appear in two entries only for `source:react` and `source:heuristics`, which look at files that a language area also covers, so do not add the counts of all entries up.
- **Standards map** (`standardsCoverage`): one entry for each OWASP Top 10 2025 category (A01 to A10) and each CWE Top 25 2025 entry. A rule is mapped to an entry through the OWASP and CWE ids in its own `standards` metadata (the same data as `pgard rules list`), by exact id: no parent or child CWE is inferred. The state is:
  - `rules_ran`: at least one mapped rule ran and nothing limits it: every area it ran in completed, no code area was partial (a partial `source:large-files`, `source:unreadable`, `source:config` or an ORM such as `source:orm:typeorm` limits every entry that code rules map to), every scope that has a mapped rule ran (a history-only scan cannot be `rules_ran` for an entry that code rules also map to), each language present in the project is covered by a completed mapped rule, and no rule looked at 0 targets. Rules for history and web look at tracked files and the running service whatever the language is, so the language check applies to entries that code rules map to.
  - `rules_partial`: some mapped rules ran, but one of those conditions does not hold. The reason says which.
  - `not_run`: rules map to the entry, but none ran (their scope was not selected or could not run).
  - `no_rules`: no PGARD rule maps to the entry (reason `no rules`).

  Each entry lists the rules that ran (`ruleIds`), every rule that maps to it (`mappedRuleIds`) and a short reason. OWASP entries also carry `breadth`: how many of the CWEs in the category's "List of Mapped CWEs" have at least one PGARD rule (for example 1 of 6 for A03). CWE Top 25 entries have `breadth: null`, because a CWE is one weakness.

- **What `rules_ran` does not mean.** It does not mean the weakness is absent, that every way to commit it is detected, or that the category is covered; several categories are mapped to a narrow rule, so read `breadth` and the rule ids. OSV and other advisories are not part of a scan (PGARD ships no vulnerability database), so they never count: A03 Software Supply Chain Failures is mapped only to `PG-HYGIENE-001` (committed dependency directories), and lockfiles are not examined.

The terminal summary has one line per OWASP category and counts for the CWE Top 25; use `--format json` for the per-entry detail and the rule statistics. Older stored results (schema 1.0) have neither field and are read as before; the terminal then shows no standards section. The reports and the dashboard show the map and the statistics too (see [Rule details, standards and statistics in reports and the dashboard](#rule-details-standards-and-statistics-in-reports-and-the-dashboard)). A launcher that injects a web scanner must also pass the web rule catalog (`webRules`), otherwise `runScan` refuses to run.

### Rule details, standards and statistics in reports and the dashboard

The HTML and PDF reports and the dashboard show the same information as the terminal and more:

- **Per finding:** the standards the rule maps to (OWASP Top 10 2025, CWE, and SEI CERT Java where the rule maps to a CERT rule), each as a link to its official page, and the rule's vulnerable and safe code examples. A finding's Impact and Recommendation already are the rule's rationale and remediation in the chosen language; the rule's general text is added only when the finding carries its own different text, so the two never contradict each other. Examples are code blocks shown as text (escaped in HTML, plain text in React), in a collapsed `<details>` section in the HTML report and the dashboard. Links open in a new tab with `rel="noopener noreferrer"`; the reports have no scripts and the dashboard's CSP is unchanged. A CERT rule that is only linked through a CWE id is marked `(via CWE-89)`.
- **Per scan:** the **Standards coverage** map (one row per OWASP Top 10 2025 category with its state, `breadth`, rules and reason, and the CWE Top 25 in a collapsed list) and the **Rule statistics** table (rule, area, targets examined, findings, status; collapsed in HTML). The map uses the same states and wording rules as the terminal: `Rules ran` means neither safe nor covered, and nothing is green. Suppression and baseline counts stay in the summary line and the notices above it.
- **PDF layout.** A PDF cannot collapse, so the findings stay short: each finding lists its standards as clickable ids. The rule statistics, the CWE Top 25 list, the examples (once per rule, not once per finding) and the full standards URLs (so a printed copy keeps them) follow the findings in appendices A to C.
- **Older results.** A result written by schema 1.0 has neither `ruleStats` nor `standardsCoverage`; the reports and the dashboard show a short note instead of the two sections and no error. Rule details need the rule catalog: the CLI and the dashboard always pass it, and a report rendered without `ruleTexts` shows the findings without them.
- **Licensing.** Only ids, titles and links of the standards are shown, never their text. The report footer and the standards panel carry the attribution required by [NOTICE.md](NOTICE.md): OWASP Top 10:2025 under CC BY-SA 4.0, CWE under the MITRE CWE Terms of Use, and SEI CERT under CC BY 4.0 (not endorsed by Carnegie Mellon University or the SEI).

### Language of rule texts

Rule titles, the impact text and the fix text can be shown in Korean or English. The language is chosen in this order: `--lang en|ko`, then the environment variable `PGARD_LANG` (`en` or `ko`), then the system locale (`LC_ALL`, `LC_MESSAGES`, `LANG`; the first one that is set decides, and a value starting with `ko` selects Korean; on Windows, where these are usually unset, the runtime locale is used), and otherwise English. Values are case-insensitive (`KO` works). An invalid `--lang`, `--report-lang` or `PGARD_LANG` value is a usage error (exit 2); `PGARD_LANG` is checked only by the commands that show rule text (`scan`, `rules list` and the menu), so `doctor`, `login`, `logout` and `history clear` ignore it.

- **Terminal:** the whole scan result screen (headings, labels, status words, charts, notices, the note that `testDirectories` classified findings as test code, the comparison with the last scan), the progress and status lines on stderr, and the first-run storage notice use that language, as do the rule titles, impact and fix lines and the titles in `pgard rules list`. Korean text is padded by display width (Korean characters take two columns), so columns line up. Not translated: paths, evidence, reasons quoted from `pgard.config.json`, coverage notes written by the scan, authorization reasons and the official titles of standards. Prompts and the other commands' messages (sign-in, App install, report export) stay English for now.
- **Reports:** `--report-lang en|ko` (default: the terminal language) sets the language of the whole report chrome (headings, labels, table headers, summary, notices, disclaimer and the new standards and statistics sections) as well as the rule titles, impact and fix texts, and `<html lang>` follows it. The PDF uses the embedded Korean font (its subset covers all rule texts and examples; a test checks that). Evidence, locations, authorization reasons, coverage notes and the reasons in the standards map are data from the scan and stay as written (English).
- **Dashboard:** rule titles, impact and fix texts follow the dashboard's own language toggle, and the report downloads use the same language. The server only sends the rule metadata of both languages (`/api/rule-texts`: titles, texts, standards links and examples); no scan data is added. If that request keeps failing, the dashboard shows a notice and the rule texts stay in English.
- **JSON output** (`--format json`) and stored results are unchanged and always English.
- **Finding-specific text:** some findings carry their own text instead of the rule's default (for example the recommendation of a committed dependency directory). That text is shown as it is, in English, and the rule default is never shown next to it. Findings from dependency advisories are also shown as they are.

### Grouping and collapsing

Findings are ordered by severity (critical, high, medium, low, info), then confirmed before suspected before informational, then by location. Findings with the same rule and cause form one group: the title shows the number of locations and the line names up to 3 of them (`src/db.ts:10, src/db.ts:30, src/orders.ts:7 and 2 more`), with the evidence when all members share it, otherwise the line `Evidence: varies by location`. The result carries no cause text (only a fingerprint that includes the line), so "same cause" means the same rule, title, severity, status, confidence, location kind and context.

When more than 5 findings (the constant `COLLAPSE_THRESHOLD`) come from test, fixture or vendored code, the CLI replaces the listing of the lower-severity ones (medium, low, info) with a summary: the count, counts per context and per rule, and the severities, plus how to see everything. Exactly 5 are still listed. Critical and high findings, and findings in your own code, are never collapsed. `--all-findings` lists everything, and so does the HTML report (`--report html --output-dir <dir>`). The headline names the critical and high findings in test code, for example `plus 8 in test or fixture code (1 critical, 2 high)`, and the status counts (`Findings (6): 1 confirmed, 5 suspected (needs review)`). Without a terminal or with `NO_COLOR` the output is the same text without colors.

### Suppressions

The `suppressions` list of `pgard.config.json` marks findings you have reviewed as false positives or accepted. A suppression changes **where a finding is listed, never whether it exists**. The config is part of the scanned repository, so it is untrusted: everything a suppression does is shown, and it cannot change authorization, the status or the exit code.

- **Matching.** An entry matches a finding when the rule id is equal and the path pattern (same syntax as `exclude`) matches the finding's repository-relative path. It applies to every finding that has a file path: source code and Git history (the file the secret is in). The first matching entry in file order is the one recorded on the finding; every active entry still counts the findings it matches.
- **Findings without a file path** (local web findings, which have a URL) are matched only by an entry whose pattern matches every file (`**`, `*`). Such an entry is always flagged as a wildcard (below). A narrow path such as `src/**` never matches a web finding.
- **Expiry.** `expires` (`YYYY-MM-DD`) is valid through the end of that day in UTC. An expired entry is **not applied**: its findings stay in the regular groups, and the entry is reported as a warning.
- **Nothing is deleted.** A matched finding stays in the result with `suppression: { reason, expires?, source: "pgard.config.json" }`, and the result carries a `suppressions` summary (suppressed count, how many are critical, and each entry with the number of findings it matched, its state `active` or `expired`, and whether its path matches every file). The JSON result and the stored result contain everything. The `source:config` coverage note counts them (`2 suppressions (5 findings suppressed, 1 expired, not applied)`).
- **Always visible, with severities.** Every count of suppressed findings carries a breakdown by severity: the terminal result prints `Suppressed by pgard.config.json: 12 (12 high)` above the findings, adds `12 suppressed (12 high)` to the severity headline, keeps suppressed findings out of the severity groups and charts, and lists them in their own group `Suppressed (N)`. When nothing unsuppressed is left, the "no findings" sentence says so: `No unsuppressed findings outside test or fixture code in the areas that ran (12 suppressed: 12 high)` (terminal, HTML, PDF, dashboard). By default the group shows counts per rule and severity; `--all-findings` lists every suppressed finding with the reason (in the config's own words, quoted as such). The HTML report and the dashboard show the group as a collapsed section (a `<details>` element) with the count in its title; the PDF cannot collapse, so it lists them in full after the other findings. The JSON `suppressions` summary has `bySeverity`.
- **High and critical findings.** A critical (or high) finding may be suppressed, but never quietly: a `!` warning says `K suppressed findings are high or critical (H high, C critical)` in the terminal, both reports, the dashboard (English and Korean) and the `source:config` coverage note, the severity breakdown is in every count, and suppressed critical findings are always listed in full, also without `--all-findings` (the HTML section is open). Policy rationale: a hard ban would make the config unusable for a real, reviewed exception, while silent suppression of the worst findings is what an attacker-edited config would want.
- **Broad, long-lived or wildcard suppressions are flagged.** A `!` warning appears for an entry whose path matches every file (`**`, `*`, `**/*`), for an entry that matches more than 10 findings (`BROAD_SUPPRESSION_THRESHOLD`), for **more than 10 findings suppressed in total**, however many entries share them (twelve narrow entries cannot slip under the per-entry limit), for an expired entry, and when every finding of the scan is suppressed. An `expires` date more than a year ahead (366 days, `MAX_SUPPRESSION_HORIZON_DAYS`) is a warning too: a suppression is a promise to look again, and `9999-12-31` is no expiry at all. Active entries with no `expires` get a quiet line in the terminal (`N suppressions have no expiry date`). The same warnings appear in the HTML and PDF reports and in the dashboard (English and Korean). A `ruleId` is always one exact rule id (`PG-SQL-001`); there is no rule wildcard.
- **Work budget.** Suppression matching shares the glob work budget (500 million table cells). If it runs out, the remaining findings are **not** suppressed, and a warning says matching stopped early (`incomplete` in the summary): the failure direction is "more is shown".
- **Status and exit code are unchanged.** The overall status comes from coverage, not from findings, so a suppression can never turn a `partial` scan into `completed`. An invalid config applies no suppression at all, like it excludes nothing.
- **Comparison.** Suppressed findings take part in "Since the last scan" and in the baseline like any other finding (the identity does not look at suppression), so suppressing a finding never makes it read as "no longer reported".

### Baseline

A baseline is a scan of this repository that you accept as the reference. Later scans group the findings that match it as `In baseline (N)` and highlight the new ones. A baseline never hides a finding: counts are always shown, and the status and exit code do not change.

```text
pgard baseline set [--from-current]
pgard baseline show
pgard baseline clear
```

- **`baseline set`** uses the **newest stored scan** of this repository: no new scan, no network traffic except the authorization check. This is the usual flow: run `pgard scan`, review it, then `pgard baseline set`. A partial scan is accepted with a warning (findings in the parts it did not cover will read as new). It fails with a hint when nothing is stored yet.
- **`baseline set --from-current`** scans code and Git history now (like `pgard scan`, with the same output) and uses that scan.
- **`baseline show`** prints when it was set, from which scan and commit, its status and scopes, and how many findings it holds. **`baseline clear`** deletes it (the stored scans stay).
- The baseline is kept **per verified repository** (GitHub's numeric repository id, like stored results), so these commands run the authorization gate first and refuse a repository that is not verified (exit 3). Nothing is uploaded.
- **Matching** uses exactly the identity and one-to-one pairing of "Since the last scan" (rule, path, redacted evidence shape, not the line number), so code that only moved is still in the baseline and a second copy of a baselined finding is new. **Suppressed findings are left out of the baseline** when it is set (and ignored if an older baseline holds them): a suppression is temporary, and a finding the baseline swallowed with it would stay hidden after the suppression is removed or expires. Left out, it comes back as new then (`baseline set` says how many were left out). A finding that is both suppressed and in the baseline is listed as suppressed.
- **What a scan shows.** `Baseline (set 2026-10-20): 6 in baseline (1 critical, 5 high), 3 new` above the findings (`matched` and `new` in the JSON exclude suppressed findings, which are counted under `suppressions`; `new` also counts test and vendored findings, which the `New findings` headline leaves out); the headline becomes `New findings by severity` and counts only the new ones; each new finding group is under `New findings since the baseline (N)` (the dashboard and reports mark them `NEW`); the others are under `In baseline (N)`, summarized by rule and severity by default, in full with `--all-findings`; critical findings in the baseline are always listed in full. The `!` notices say when new findings sit in areas the baseline did not fully cover (`newInUncertainAreas`), or when PGARD was updated since.
- **JSON.** `baseline: { setAt, scanId, revision, total, matched, new, newInUncertainAreas, toolVersionChanged }` and `inBaseline: true` on matching findings. Stored results carry them too.
- **Storage.** `repos/<repository id>/baseline.json` in the result store, with the same rules as stored results: `0700` directories and `0600` files on macOS and Linux, symbolic links refused (a link in place of the file is never followed, written through or read), atomic write, a size cap, a refusal to overwrite a file written by a newer PGARD, and a refusal to store a result that contains a local path. It holds a redacted copy of the scan, is not subject to the 20-scan, 90-day retention, and is read back through `readScanResult`. The file records the repository id it was set for, and a baseline for another repository, or a file that other users can write (group or world write bit on macOS and Linux), is refused with a warning. A damaged baseline is an error (`pgard scan` warns, applies nothing and shows every finding), never silently "no baseline".
- **Opt out.** `pgard scan --no-store` and `PGARD_NO_STORE=1` neither read nor apply a baseline (every finding is listed as usual). With `PGARD_NO_STORE=1` the `baseline` commands refuse to run (exit 2). Dashboard scans never read the store, so the dashboard does not apply a baseline.
- **`pgard history clear` also deletes the baseline** (`--all`, `--repo owner/name`; the message says how many). A baseline is stored scan data, and a leftover one would keep grouping findings after you asked for everything to go.

### SARIF output

`pgard scan --format sarif > pgard.sarif` writes the redacted result as [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html) to stdout (progress and messages go to stderr, exit codes are unchanged). To keep a file, redirect stdout; PGARD has no output-file option for SARIF, and `--report`/`--output-dir` still only write HTML and PDF reports. **PGARD never uploads anything**: sending the file to GitHub or an IDE is your step.

**When not to upload.** GitHub code scanning does not display PGARD's `toolExecutionNotifications`, and it closes existing alerts that are missing from an upload. A SARIF of a scan that did not fully run would therefore close alerts for areas that were never checked. Upload only when the exit code is `0`. Exit code `3` (blocked), `4` (partial) or `5` (failed) means do not upload; PGARD also prints "Do not upload this SARIF" on stderr for them. Such a file also has `executionSuccessful: false`; GitHub is expected to reject it as an unsuccessful execution, but that is not in GitHub's documentation, so the exit code remains the main safeguard. Projects that import ORMs or query builders PGARD does not analyse (TypeORM, Sequelize, Knex, Drizzle, MikroORM, Objection, Kysely, and for Go ent, Bun, XORM, SQLBoiler, go-pg) always get a partial result (exit 4), so their SARIF is not uploadable by design. There is no CI workflow example: the authorization gate needs a GitHub sign-in that a CI runner does not have today, so a runner would produce a blocked, empty SARIF. A local flow:

```sh
pgard scan --format sarif > pgard.sarif && \
  gzip -c pgard.sarif | base64 | tr -d '\n' > pgard.sarif.b64 && \
  gh api -X POST repos/OWNER/REPO/code-scanning/sarifs \
    -f commit_sha="$(git rev-parse HEAD)" -f ref="$(git symbolic-ref HEAD)" \
    -F sarif=@pgard.sarif.b64
```

(`&&` uploads only after exit code 0. The commit must already be pushed, HEAD must not be detached, and the token needs the `security_events` scope: `gh auth refresh -s security_events`. The file is passed with `-F sarif=@file` so a large report does not hit the argument-length limit. If you use `github/codeql-action/upload-sarif` instead, it logs one fingerprint-mismatch warning per result; that is expected.)

**Categories.** Each result carries `automationDetails.id` `pgard/<scopes>/` (for example `pgard/code+history/` for a default scan, `pgard/code/` for `scan code`). GitHub treats each id as its own category and closes alerts only when the same variant is uploaded again, so uploading `scan code` never closes the alerts of a default `scan`.

How the result maps:

- **Rules.** One entry in `tool.driver.rules` for every rule that ran or produced a finding: short description (title), full description (rationale), `help.text` (remediation), `helpUri` (the official CWE page, else the first standards link) and `properties.tags` (`security`, `CWE-n`, `external/cwe/cwe-n`, `OWASP-A0x:2025`).
- **Severity.** `level`: critical and high are `error`, medium is `warning`, low and info are `note`. `security-severity` is a numeric string: critical `9.5`, high `8.0`, medium `5.5`, low `3.0`, info `1.0`. GitHub reads it only on the rule, where PGARD sets the strongest severity among that rule's findings in the run, so GitHub can show a lower-severity result at the rule's higher severity. Each result also carries its own value for other tools.
- **Locations.** Only findings with a repository file path are in the file (GitHub rejects a result without a physical location). Each has a repository-relative `artifactLocation.uri` (`uriBaseId` `%SRCROOT%`) and a region with start and end line (no region when it has no line). A history finding also has its commit in `properties.pgard.commit`. **Web findings are left out** (they have no file, and PGARD does not invent paths): the file says how many and for which rules in an `error` notification and in `runs[0].properties.pgard.omittedFindings`, and the CLI prints a warning on stderr. Use the text or JSON output or a report for them.
- **Fingerprints.** `partialFingerprints["pgardFindingIdentity/v1"]` is the same line-insensitive identity the baseline and scan comparison use, so a finding that only moves keeps its fingerprint. `primaryLocationLineHash` (the only one GitHub uses) is that identity plus `:n`, where n counts results with the same identity in the file, so identical findings on different lines do not collide. Findings in history keep a stable identity even when the file was later deleted.
- **Suppressed and baseline findings.** A finding suppressed in `pgard.config.json` stays in the file with `suppressions: [{kind: "external", justification}]`, so it stays counted. When a baseline exists, `baselineState` is `unchanged` for findings in it and `new` for the others; suppressed findings get no `baselineState`. Without a baseline it is never set.
- **Areas that did not run.** Each `partial` or `not_tested` area is a `warning` in `runs[0].invocations[0].toolExecutionNotifications`. `executionSuccessful` is `false` whenever the scan is blocked or failed or any requested area is `partial` or `not_tested` (for example `scan web` without a confirmed target); those also get an `error` notification. GitHub is expected to reject a file with `executionSuccessful: false` (not documented by GitHub; the exit code remains the main safeguard). Areas you did not select are not listed. Other tools may show the notifications; GitHub does not.
- **Redaction.** The text is redacted exactly like the JSON output; secret values never appear.

### Stored results

`pgard scan` keeps the finished result so that later work can compare scans. This is new since the MVP, which kept nothing. Only CLI scans are stored for now: the dashboard still keeps its results in memory and discards them when it stops, and `project verify` is never stored.

- **Where.** In the per-user app-data folder, never in a project: `~/Library/Application Support/pgard` on macOS, `$XDG_DATA_HOME/pgard` (default `~/.local/share/pgard`) on Linux, `%LOCALAPPDATA%\pgard` on Windows.
- **What.** One file per scan, under the numeric GitHub repository id from that run's authorization (no repository name in the path). The file is the redacted scan result, the same JSON as in [`docs/RESULT_SCHEMA.md`](docs/RESULT_SCHEMA.md): scan id and times, PGARD version, requested scopes, overall status; `owner/name`, the HEAD commit SHA and, for web scans, the `127.0.0.1` origin; the authorization decision and the five checks with their reasons, which name the signed-in GitHub login, the owner account or organization and your role; coverage per area; and every finding with rule, severity, repository-relative path and line (or local URL, or commit), a redacted evidence snippet, impact and guidance. It does not contain absolute paths, the project root, tokens, or whole source files, and it is never read back to authorize anything: the five checks still run on every scan. A scan is stored only when the gate allowed it in this very run and it did not end `blocked` or `failed`.
- **Retention.** The last 20 scans per repository, and none older than 90 days. Pruning runs after each save (constants `RETENTION_MAX_SCANS_PER_REPO` and `RETENTION_MAX_AGE_DAYS` in `@pgard/result-store`).
- **Protection.** On macOS and Linux the directories are `0700` and the files `0600`, checked after writing; PGARD does not follow a symbolic link for the store folder or its files. Files are written to a temporary file in the same folder and renamed, so a concurrent scan never sees a partial file. On Windows the mode bits do not apply: the folder inherits the access rules of your `%LOCALAPPDATA%` profile folder, and PGARD does not change or check them.
- **Reading back.** Always through `readScanResult`, after a file size cap (8 MiB). A corrupt, oversized or unsupported file is skipped with a warning, and PGARD never writes over a file that a newer PGARD wrote (a newer `schemaVersion` minor).
- **Comparison with the last scan.** After a scan is stored, PGARD compares it with the newest earlier stored result of the same repository and prints one line (local time), for example `Since the last scan (2026-10-25 14:02): 2 new (1 in areas not fully compared: history:commits), 1 no longer reported, 9 unchanged (3 moved)`. The first scan prints nothing, and so does `--no-store`. With `--format json` the line goes to stderr and stdout stays a single JSON document. If the previous scan was of another commit, the line shows its short commit (`, at abc1234`).
  - **Matching.** A finding is matched by rule, file path and the redacted shape of its evidence, not by line number, so code that only moved is "unchanged (moved)", not "gone + new". Web findings use rule, URL without query and the evidence without version-like values (header and cookie names count); history findings use rule, path, commit and evidence. Two findings with the same identity are paired by nearest line; this means two findings of the same shape in one file are treated as one finding that moved, even if one was removed and another added elsewhere in that file. A pair whose severity or status changed is counted ("1 changed severity or status").
  - **"No longer reported" is not "fixed".** The code may also have been skipped, renamed or deleted. A previous finding is counted as no longer reported only when the place was analyzed completely in both scans. It is not counted, and the line says so (`Some findings could not be compared because history:commits was only partially scanned`), when: its area was partial, not tested or ran in only one scan; files in that scope were skipped (over 1 MiB, an unsupported ORM, a dependency directory, any symbolic link to a file or directory, or a directory that could not be read) or the set of skipped items changed (PGARD compares a short hash of the skipped paths, not the paths); the web address differs; or PGARD itself was updated between the scans (the line then says so).
  - **New findings are never hidden.** Every finding that was not in the previous scan counts as new. If its area was only partially scanned before, or was not part of the last scan at all, it is counted in the qualifier, `(N in areas not fully compared: <area>)`, because it may have been there already.
  - **Permanent partial areas.** A repository that always has a partial area (a source file over 1 MiB, a detected `source:orm:*` package PGARD cannot analyze, history blobs over 1 MiB) will rarely or never see "no longer reported" for the findings that area blocks. That is deliberate: those scans never prove that the place was analyzed, so a missing finding could be a skipped one. Such findings still pair when they are present in both scans.
  - **Storage.** Nothing is stored for the comparison: it is computed from the two stored results, read with the same size cap and `readScanResult` as above (the newest readable file is used; a corrupt or newer-schema file is skipped with a warning). The full comparison view is not part of the CLI yet.
- **First run.** The first time a scan is stored, PGARD prints a notice on stderr that says where results go and how to turn this off or delete them. It is shown once; a marker file `.notice-shown` in the store folder records that.
- **Opt out and delete.** Pass `--no-store` or set `PGARD_NO_STORE=1` to store nothing (and to ignore a [baseline](#baseline)). `pgard history clear --all` deletes everything, baselines included (`--repo owner/name` one repository). To delete by hand, delete the `repos` folder inside the store folder (`pgard/repos`), not the whole `pgard` folder, which other PGARD data may share.
- **Advisory data is separate.** `pgard advisories update` stores public OSV vulnerability data under `advisories/osv/` in the same app-data folder (about 5 MB; not scan results, not touched by `pgard history clear`, not affected by `--no-store`). It is written only by that user-run command, which downloads from the OSV export host and uploads nothing. See [Privacy and network traffic](#privacy-and-network-traffic).

### Findings in test or fixture code

### Findings in test or fixture code

Findings in test or fixture code are listed after the other findings, in their own group: **In test or fixture code (N)**. Their rule, severity and evidence are unchanged, but their confidence is capped at `low`. The headline count and the severity chart cover regular code only (for example `Findings by severity (3 total) - plus 2 in test or fixture code`). These findings are not dropped, because a real secret committed in a test is still exposed. The dashboard and the HTML/PDF reports list them all in this group. The terminal view lists them too, except that when there are more than 5 the medium, low and info ones are replaced by a summary (see [Grouping and collapsing](#grouping-and-collapsing)); critical and high ones stay listed.

The classification is by path only, never by file content. A file is test or fixture code when:

- its name matches `*.test.*`, `*.spec.*` or `*_test.go`, or
- it is under a `__tests__/`, `__mocks__/`, `__fixtures__/`, `fixtures/` or `testdata/` directory, or
- it is under a `test/` or `tests/` directory, **unless** it is a configuration file: `.env*`, `.npmrc`, `Dockerfile*`, `settings.py`, `*_settings.py`, `config.py`, or a `.yml`, `.yaml`, `.tf`, `.tfvars`, `.properties`, `.ini`, `.toml`, `.json`, `.conf`, `.cfg` or `.xml` file. Such files may configure a real deployed test environment, so they count as regular code.

Directory names are matched case-insensitively. The rule applies to findings from every scope, so a `.env` under `fixtures/` is a test finding, while `deploy/test/.env` is not.

### Suggestions in third-party or vendored code

Findings in third-party dependency code committed to the repository are shown as suggestions, not as regular findings: you do not own that code and cannot fix it there. They are listed last, after the test or fixture group, in **Suggestions: in third-party/vendored code (N)**, with the note "This code is a committed dependency, not your code. Review it if it's unexpected; otherwise consider removing it from Git." Their rule, severity and evidence are unchanged, but their confidence is capped at `low`. The headline count and the severity chart do not include them (for example `Findings by severity (3 total) - plus 2 in test or fixture code, 5 suggestions in vendored code (1 high)`; critical and high suggestions are counted in the parentheses so they are not hidden in a total). They are never dropped, because a real secret committed in `node_modules/` is still exposed. Coverage, the overall status and exit codes do not change. The dashboard (with the same filters) and the HTML/PDF reports list them all in this group, and the terminal view summarizes lower-severity ones when more than 5 findings come from test, fixture or vendored code (see [Grouping and collapsing](#grouping-and-collapsing)), and the `PG-HYGIENE-001` suggestion (see [Git history checks](#git-history-checks)) is listed in the same group.

The classification is by path only, never by file content. A file is vendored when a directory in its path is:

- exactly `node_modules`, `bower_components`, `jspm_packages` or `Pods`, anywhere in the path, or
- exactly `vendor` or `third_party`, **unless** a directory before it is `src`, `app` or `lib` (in any letter case, so `Src/vendor/` is also your own code). Those names are also common first-party module names (`nest g module vendor` creates `src/vendor/`), so `src/vendor/vendor.service.ts`, `packages/web/src/third_party/a.ts` and `app/vendor/client.rb` are your own code.

Also:

- Whole directory names only. The vendored names are matched case-sensitively, because package managers create them exactly so and a lowercase `pods/` is often Kubernetes configuration: `src/vendored.ts`, `my_node_modules_x/index.js`, `Vendor/` and `k8s/pods/` are not vendored.
- Go and PHP (Composer) `vendor/` directories at the top of a project or package (`vendor/`, `api/vendor/`) are both dependency copies, so both count.
- Build output such as `dist/` or `build/` is your own output and is not vendored.
- A path that is both vendored and test code (`node_modules/pkg/test/a.js`) is vendored.

HTML and PDF reports are rendered from the same redacted result. The HTML report is a single file with no scripts and a strict CSP. Reports are written only to the directory you name, never overwrite existing files, and are created with mode `0600` (not possible on Windows, see [Requirements](#requirements)). Keep reports outside the repository so they are not committed by mistake.

## Dashboard

`pgard dashboard` finds the Git root of the current directory, shows it and asks `Start the dashboard for this project? [y/N]`. It needs an interactive terminal; without one it exits with code 2. After you confirm, it starts the local web app and prints a private session URL:

```text
PGARD dashboard is running on 127.0.0.1 only.
Open this private session URL in your browser (valid until you stop the dashboard): http://127.0.0.1:<port>/#token=<random>
```

The dashboard runs its own scans (it never reads or writes the results the CLI stored, and its own scans are not stored). It shows the `suppressions` of `pgard.config.json` like the CLI does (a count in the headline, warnings for critical, wildcard, broad and expired entries, and a collapsed `Suppressed (N)` section); it does not apply a baseline, because that lives in the CLI's result store. It shows the authorization checks and the GitHub device code, lets you pick and confirm a local service, select scopes, follow progress, filter findings (test or fixture findings and suggestions in vendored code are shown in their own groups) and download HTML/PDF reports through the browser (the same redacted report the CLI writes; the dashboard never writes files to a path you type). It reuses the GitHub sign-in saved in the OS keychain on the server side; the token never reaches the browser. There are two sign-out buttons: **End dashboard session (keep keychain sign-in)** forgets the session in this dashboard only, and the next check reuses the keychain sign-in; **Sign out and remove from OS keychain** also deletes the saved sign-in (for the CLI too). If `pgard login` switches to another GitHub account while the dashboard runs, the dashboard drops its last check, so local service discovery and probes need a new check. Stop the dashboard with Ctrl+C: its GitHub session ends (the keychain sign-in is kept) and all results are discarded.

When a device code is needed, the dashboard shows an **Open the GitHub sign-in page** button and, unless `pgard dashboard --no-browser`, opens the page itself. When the authorization panel is blocked only because the PGARD GitHub App is not installed for this repository and you can approve (or GitHub cannot show your organization role yet; the CLI's wording is used), it shows an **Install the PGARD GitHub App** button (opens a new tab), checks owner approval again every 5 seconds for up to 10 minutes, and then runs the full check again automatically. The server enforces both limits: at most one re-check every 5 seconds, and only within 10 minutes of when the check finished, so reloading the panel does not extend the wait. Otherwise it shows the same `Ask an owner of <account> ...` link as the CLI.

Port discovery, identity probes and target confirmation are allowed only after the dashboard's latest authorization check for this project passed, and only for 30 minutes after that check finished. The dashboard shows when this window ends; after that (or if the system clock moves back), you must check again before it contacts local services. A new check or a sign-out closes the window at once and aborts probes that are still running, and the page drops port lists and probe results from an earlier check. Each scan runs the full authorization check again regardless of this window.

The dashboard is available in Korean and English. It follows the browser language (any Korean setting picks Korean, otherwise English) and has a **한국어 / English** toggle in the header; the choice is remembered in the browser. Rule texts in finding details (title, impact, fix, standards, examples) and the standards and rule-statistics panels follow the same toggle; other text that comes from the scan itself (evidence, authorization reasons, coverage notes) stays in English for now.

### How the dashboard protects itself

- It binds to `127.0.0.1` only, on a free port.
- A random 32-byte session token is passed in the URL **fragment**, so the browser never sends it in requests or `Referer` headers. The page removes it from the address bar and keeps it in memory. Do not share the URL.
- Every API call must carry the token in the `x-pgard-token` header. The `Host` header must be exactly `127.0.0.1:<port>` (DNS rebinding protection). Requests from another `Origin` and cross-site requests are refused, and no CORS headers are sent.
- Every response has `Cache-Control: no-store`, a strict Content-Security-Policy, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
- The browser cannot choose or read project files. The project root is fixed when the dashboard starts. The browser supplies no path at all: a report is rendered by the server from the redacted result and sent as a normal browser download (`GET /api/reports/html` or `/pdf`, with the session token), so nothing is written to disk by the dashboard. The browser receives only redacted findings (with short redacted snippets), never full source files or the GitHub token.

## Privacy and network traffic

- Your code, Git history and scan results are processed on your computer and are not uploaded anywhere. Results of `pgard scan` are kept in your app-data folder unless you opt out with `--no-store` or `PGARD_NO_STORE=1`, and `pgard history clear --all` deletes them (see [Stored results](#stored-results)). Dashboard results are kept in memory and discarded when the dashboard stops. Reports you export are saved where you choose.
- The GitHub sign-in is saved in the OS keychain, never in a file, and never sent to the browser. Without a keychain it is kept in memory only. See [Saved sign-in](#saved-sign-in-os-keychain).
- Scans and every command except `pgard advisories update` contact GitHub only: the device-flow sign-in (and refreshing a saved sign-in) and GitHub API calls that read the metadata needed for authorization (your identity, the app installation, your organization membership (for organization repositories), your access and your contributions). To check contribution, PGARD sends the SHAs of local commits to GitHub (for the verified owner, only to check that local history shares a commit with the default branch). `pgard doctor` also checks whether `api.github.com` is reachable.
- After authorization passes, PGARD sends one `GET /` to each discovered listening port on `127.0.0.1` to show its identity. The web checks then send requests only to the service you confirmed.
- The one other destination is the OSV export host, `osv-vulnerabilities.storage.googleapis.com` (the official bucket behind [osv.dev](https://osv.dev/)), and only when you run `pgard advisories update` yourself. It downloads public vulnerability data (about 220 MB for npm and 13 MB for Go at the time of writing) with plain `GET` requests over https. Nothing is uploaded: no package names, no lockfile contents, no project or user data, no GitHub sign-in. The host is pinned; other hosts, plain http and redirects away from the host are refused, and there are size and time limits. A scan never starts this download and never queries OSV per package, and `pgard doctor` only reads the age of the local copy. The data is stored under your user data directory (`~/Library/Application Support/pgard` on macOS, `$XDG_DATA_HOME/pgard` or `~/.local/share/pgard` on Linux, `%LOCALAPPDATA%\pgard` on Windows) in `advisories/osv/`; delete that folder to remove it. During an update the download needs about 220 MB of temporary space next to the stored data (it is deleted when the update ends); the stored result is about 5 MB.
- The OSV download has no published checksum to verify against: PGARD records the archive's SHA-256, size, source URL and time, but its integrity rests on HTTPS to the pinned host (trust on first use). The zip and per-record CRC-32 checks detect damage and truncation, not tampering or authenticity. Google operates the bucket, so it sees the requesting IP address and the time of the request, like any download.
- PGARD does not ship a vulnerability database and does not query one during scans.

## Out of scope

- Direct database connections
- Docker or container configuration
- Performance and load testing
- Scanning remote (non-loopback) services
- Attack requests, form submission and other state-changing requests
- Logged-in (authenticated) web browsing (#45). The `web:authenticated` area is always `not_selected`, and PGARD never asks for application passwords.
- Matching dependencies against vulnerability (CVE/advisory) data: not implemented yet. Only lockfile parsing and the user-run OSV data download exist.

## Accuracy

Each rule is measured against a labelled corpus under [`tests/corpus/`](tests/corpus/): vulnerable (`positive`) and safe (`negative`) samples for the source rules, generated Git repositories for the history rules, and loopback servers for the web rules. `npm run build && npm run corpus` scans them all (the runner uses the built packages), prints true positives, false positives, false negatives, precision and recall per rule, and writes the table to [`tests/corpus/RESULTS.md`](tests/corpus/RESULTS.md). CI fails when a rule drops below its recorded threshold, when a sample's result changes without the expected-failure list being updated, or when `RESULTS.md` is out of date.

Read the numbers with care. The corpus is small (roughly ten samples per rule) and was written by the PGARD authors, so it shows how the rules behave on cases we thought of, not how often they are right on your code. It deliberately includes hard cases the rules miss or wrongly report; those stay in the corpus and are listed in `RESULTS.md` with a reason, never deleted. A high score here does not mean a project is secure.

Guards lower confidence; they never hide a finding. The injection rules (SQL, command, path, SSRF) suppress a finding completely only when the value is fixed by the expression itself: a literal, a numeric coercion such as `Number(x)`, a module-level constant set to a literal, or `shell-quote`'s `quote()`. When safety rests on something PGARD only infers (a `startsWith(ROOT + sep)` check, a hostname allowlist, a lookup table, an alias or a local constant), the finding stays, capped at low confidence and medium severity, with a note saying what was recognised so you can verify it. In the corpus, a safe sample that is only safe through such an inference carries `expect=low` in its header, meaning its rule must report a finding on it, capped at low confidence (silence fails the check too); `RESULTS.md` also reports precision counting only medium and high confidence findings.

## Known limitations

- PDF reports embed a subset of Noto Sans KR, so Korean and English text both render. Characters the font does not have (Hanja, emoji, other scripts) are replaced with `?` and the PDF says so; the HTML report has the full text. If the bundled font cannot be loaded, the PDF falls back to a built-in Latin-1 font (Korean becomes `?`), notes this in the PDF itself, and the CLI prints a warning.
- [#45](https://github.com/JadenMeister/pgard/issues/45) Logged-in web browsing is not available: it is out of scope (see [Out of scope](#out-of-scope)).
- Contribution is checked conservatively for users who are not the verified owner: co-author trailers and unsigned direct pushes do not count, so a collaborator who only co-authored commits or pushed unsigned commits is blocked at contribution until a pull request of theirs is merged or they push signed commits.
- The dashboard's rule texts are available in Korean and English; evidence, authorization reasons and coverage notes from the scan are English only, and so are the headings and notes of exported reports.
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
| `tests/corpus`             | Accuracy corpus, runner and thresholds              |

```sh
npm ci
npm run build         # build all packages and the dashboard UI
npm run typecheck     # type-check only
npm test              # run the Vitest suite
npm run format        # format with Prettier
npm run format:check  # check formatting
npm run check         # typecheck + format:check + test
npm run corpus        # run the accuracy corpus and rewrite tests/corpus/RESULTS.md
```

CI runs `npm ci`, `npm run build`, `npm run format:check`, `npm test` and `npm run corpus:check` on pull requests and pushes to `main`.

### Documents in `docs/`

[`docs/README.md`](docs/README.md) indexes the documents in [`docs/`](docs/) and says which are current policy and which are historical. PGARD was built from three planning documents, the MVP planning record (written in Korean; these are the English translations):

- [`PGARD_AGENT_BRIEF_EN.md`](docs/PGARD_AGENT_BRIEF_EN.md): the implementation brief. It sets the product scope, the authorization gate, the scan boundaries and the definition of done.
- [`PGARD_CLI_AND_STRUCTURE_EN.md`](docs/PGARD_CLI_AND_STRUCTURE_EN.md): the command set and the layout of the apps and packages.
- [`PGARD_DEVELOPMENT_CONVENTIONS_EN.md`](docs/PGARD_DEVELOPMENT_CONVENTIONS_EN.md): the rules for commit units, messages, naming, verification and pull requests, plus the current issue, board and review workflow.

One further document is written in English and describes current behaviour: [`RESULT_SCHEMA.md`](docs/RESULT_SCHEMA.md) sets how the scan result schema is versioned and how a reader treats another version.

Where the planning documents and this README disagree, this README and the code are correct, because they reflect decisions made later.

## License

[MIT](LICENSE)

The PDF reports embed a subset of Noto Sans KR, licensed under the SIL Open Font License 1.1. See [NOTICE](NOTICE.md) and `packages/report/fonts/OFL.txt`.

PGARD also bundles reference lists (OWASP Top 10 2025, CWE Top 25 2025 and SEI CERT Java rule ids and titles). They are third-party data under their own licenses (CC BY-SA 4.0, MITRE CWE Terms of Use, CC BY 4.0) and are not covered by the MIT license. See [NOTICE](NOTICE.md).
