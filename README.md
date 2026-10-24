# PGARD

English | [한국어](README.ko.md)

PGARD (`pgard`) is a local security scanner for GitHub projects you are authorized to scan. It runs on your own computer as a command-line tool and a local web dashboard. It checks the current code, configuration and dependencies, the Git history, and (optionally) a web service you run on `127.0.0.1`.

Before every scan, PGARD checks that the repository owner approved PGARD, that you currently have access to the repository, and that you really contributed to it. Your code and the results stay on your computer.

PGARD is an MVP. It does not find every vulnerability, and "no findings" never means "secure".

> **Current status:** the PGARD GitHub App has been registered by the project owner for this repository, but PGARD has no built-in client id yet. Each user must set it in `PGARD_GITHUB_APP_CLIENT_ID`; until then every real scan is blocked (see [GitHub App and sign-in](#github-app-and-sign-in) and #42).

PGARD is released under the [MIT License](LICENSE).

## Contents

- [Requirements](#requirements)
- [Install and build](#install-and-build)
- [Commands](#commands)
- [Authorization model](#authorization-model)
- [Scan scopes and coverage](#scan-scopes-and-coverage)
- [Analyzers and rules](#analyzers-and-rules)
- [Dependency advisories](#dependency-advisories)
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

- Node.js 22.12 or newer
- Git
- macOS or Linux for local port discovery (`lsof` on macOS, `/proc/net/tcp*` on Linux). You can always type a port by hand.
- A GitHub account, and a PGARD GitHub App client id in `PGARD_GITHUB_APP_CLIENT_ID` (see [GitHub App and sign-in](#github-app-and-sign-in))

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
  pgard scan                    code, configuration, dependencies + Git history
  pgard scan code               current code, configuration and dependencies
  pgard scan history            Git history and tracked files (secrets, risky files)
  pgard scan web [--port N]     anonymous read-only checks of a local HTTP service
  pgard scan all [--port N]     code + history + local HTTP service
  pgard dashboard [--target-port N]
                                start the local web dashboard
  pgard rules list [--language js|ts|react|vue|go]
                                supported rules and data versions
  pgard doctor                  diagnose the environment (not an authorization)
  pgard login                   sign in to GitHub once and save it in the OS keychain
  pgard logout                  remove the saved GitHub sign-in from the OS keychain
  pgard --help | <command> --help
  pgard --version
```

| Command                | What it does                                                                                                                                                                                                                                                                                                                     |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pgard`                | Interactive menu: verify, scans, dashboard, rules, doctor, quit.                                                                                                                                                                                                                                                                 |
| `pgard project verify` | Runs the authorization checks and shows each one (repository, GitHub identity, owner approval, current access, contribution) as passed, failed or unverifiable, with a reason. The result is not stored.                                                                                                                         |
| `pgard scan`           | `code` + `history`.                                                                                                                                                                                                                                                                                                              |
| `pgard scan code`      | Current source code, configuration and dependency advisories.                                                                                                                                                                                                                                                                    |
| `pgard scan history`   | Committed `.env` files and secrets in tracked files and Git history.                                                                                                                                                                                                                                                             |
| `pgard scan web`       | Anonymous, read-only checks of a local HTTP service on `127.0.0.1` that you confirm.                                                                                                                                                                                                                                             |
| `pgard scan all`       | `code` + `history` + `web`. If no web target is confirmed, the result is `partial`.                                                                                                                                                                                                                                              |
| `pgard dashboard`      | Starts the local web dashboard. See [Dashboard](#dashboard).                                                                                                                                                                                                                                                                     |
| `pgard rules list`     | Lists the rule catalog grouped by scope (code, Git history, local HTTP; a rule with an unknown scope goes under "Other rules") with each rule's severity and languages, the detection criteria version, the advisory database status, and the areas PGARD does not cover. Works outside a project and makes no network requests. |
| `pgard doctor`         | Checks Node.js, Git, GitHub reachability, local port discovery, whether `PGARD_GITHUB_APP_CLIENT_ID` is set, whether a GitHub sign-in is saved in the OS keychain (and for which account; never the token), and the advisory database status. It is a diagnosis only, not an authorization. Works outside a project.             |
| `pgard login`          | Signs in to GitHub with the device flow and saves the sign-in in the OS keychain, so later scans and the dashboard reuse it. Running it again replaces the saved sign-in. See [Saved sign-in](#saved-sign-in-os-keychain).                                                                                                       |
| `pgard logout`         | Removes the saved GitHub sign-in from the OS keychain. See [Saved sign-in](#saved-sign-in-os-keychain).                                                                                                                                                                                                                          |

`pgard rules list --language <lang>` shows only the rules for that language; rules that apply to any language (Git history and local HTTP rules) are always included, and `--language react` or `vue` also includes the JavaScript/TypeScript rules. Both `rules list` and `doctor` report the advisory database status without loading a large database in full (see [Dependency advisories](#dependency-advisories)): `missing`, `invalid`, `stale` or `ok` with its version and update date, or `unverified - not fully validated` when only a quick check was possible. The path in `PGARD_ADVISORY_DB` is never printed. In `doctor`, any status other than a fully validated `ok` is a `[warn]` row.

Every command also has its own help, for example `pgard scan --help` or `pgard login --help`.

### Options

- `--port N` (`scan web` and `scan all` only): the local service port, an integer from 1 to 65535. You still have to confirm the service.
- `--target-port N` (`dashboard` only): pre-selects the local service to check. You still confirm it in the browser. The dashboard itself runs on its own free port.
- `--report html|pdf|both` and `--output-dir <dir>` (any `scan`): save a report. The two options must be used together. The directory must already exist, and existing files are never overwritten. A directory inside the Git repository needs an explicit `y` (without an interactive terminal it is refused). By default, results are only shown in the terminal.
- `--language js|ts|react|vue|go` (`rules list` only): filter the rule list by language. Rules for any language are always included; `react` and `vue` also include the JavaScript/TypeScript rules.
- `--help` / `-h`, and `pgard --version` / `-V`.

Unknown commands and options, invalid values and invalid combinations are rejected before any Git, GitHub or network activity.

### Exit codes

| Code | Meaning                                                                                                                                                                                |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | The requested scope completed (findings may exist). For `doctor`: the diagnosis completed.                                                                                             |
| 2    | Invalid command, option, value or combination.                                                                                                                                         |
| 3    | The repository, authorization or contribution check failed (the scan was blocked).                                                                                                     |
| 4    | Part of the scan did not run, so the result is partial (for example, no web target was confirmed, or the advisory database is missing, invalid or stale), or the report export failed. |
| 5    | Internal error. Details are hidden; set `PGARD_DEBUG=1` to see a sanitized message.                                                                                                    |
| 130  | Cancelled by the user.                                                                                                                                                                 |

`doctor` exits with 0 when the diagnosis completed (problems are listed as `[fail]` or `[warn]` rows) and 5 on an internal error. `pgard login` and `pgard logout` use these codes:

| Code | `pgard login`                                                      | `pgard logout`                                    |
| ---- | ------------------------------------------------------------------ | ------------------------------------------------- |
| 0    | Signed in and saved.                                               | Removed, or nothing was saved.                    |
| 3    | GitHub sign-in failed, or `PGARD_GITHUB_APP_CLIENT_ID` is not set. | `PGARD_GITHUB_APP_CLIENT_ID` is not set.          |
| 4    | No OS keychain is available, or saving failed; nothing was saved.  | No OS keychain is available; nothing was removed. |
| 5    | Internal error.                                                    | Internal error.                                   |
| 130  | Cancelled.                                                         |                                                   |

### Interactive keys

Arrow keys (or `j`/`k`) move, Enter selects, Esc goes back, and `?` shows help. Ctrl+C asks `Cancel and exit? [y/N]`. While a scan or GitHub sign-in is running, press Ctrl+C twice within 5 seconds to cancel (exit code 130).

## Authorization model

PGARD scans a repository only when it has evidence that you are allowed to. Before every scan it reports these checks (in this order):

1. **Repository.** The current directory is the root of a Git repository with valid history. The repository uses only its own objects and history (no alternates, grafts or replace refs), and it has exactly one unambiguous `github.com` remote.
2. **GitHub identity.** You sign in to GitHub with the device flow, or PGARD reuses the sign-in saved in the OS keychain (see below). Only the sign-in is reused: checks 3 to 5 always run against GitHub again.
3. **Owner approval.** The PGARD GitHub App is installed on the repository owner's **personal account**, and that installation includes this repository. Only the owner of a personal account can install an app on it.
4. **Current access.** GitHub reports that you currently have at least read access to the repository.
5. **Contribution.** Your contribution is in the default-branch history. A commit counts only if GitHub shows it in the default branch, and either it belongs to a pull request you authored that was merged into the default branch, or GitHub verified its signature and attributes the committer to you. Author names or emails, co-author trailers, unmerged pull requests, pull requests merged into other branches or forks, unsigned direct pushes and local-only commits are never accepted as proof. PGARD examines up to 30 local commits (the ancestry of `HEAD`). If none of them qualifies and more local commits exist, contribution is `unverifiable`.

Each check is `passed`, `failed` or `unverifiable`, with a reason. The checks are reported in this order, but they are not evaluated strictly in this order: for example, PGARD reads the repository from GitHub (current access) before it checks owner approval. The scan runs only if every check passed. If any evidence is missing or unclear, the scan is **blocked** (exit code 3) and PGARD reports which check failed and why.

### Organization repositories

Repositories owned by an organization are always blocked (#43). GitHub's APIs cannot prove that an organization owner, rather than a repository admin, installed the PGARD GitHub App, so owner approval is reported as `unverifiable`.

### GitHub App and sign-in

PGARD signs you in through a GitHub App using the OAuth device flow. It needs the app's public client id. PGARD has no built-in default client id yet, so you must set it yourself:

```sh
export PGARD_GITHUB_APP_CLIENT_ID=<client id of the PGARD GitHub App>
```

When sign-in is needed, PGARD shows the URL `https://github.com/login/device` and a short user code. You open the URL, enter the code and approve. The token is never printed, logged, put in process arguments or environment variables, or written to a file.

#### Saved sign-in (OS keychain)

After a device-flow sign-in (from `pgard login`, a scan, `project verify` or the dashboard), PGARD saves it in the **OS keychain**: macOS Keychain, Windows Credential Manager or the Linux Secret Service. Later CLI runs (`scan`, `project verify`) and dashboard sessions reuse it, so you do not enter a code on every scan. Only the sign-in is reused: the owner-approval, access and contribution checks still run against GitHub before every scan. Run `pgard login` again to replace the saved sign-in, for example to switch accounts.

- The entry is keyed by GitHub host and App client id. Changing `PGARD_GITHUB_APP_CLIENT_ID` never reuses another App's token.
- If the App issues expiring tokens (8 hours, with a 6-month refresh token), PGARD refreshes the access token automatically. GitHub does not require a client secret to refresh tokens that came from the device flow, so PGARD has none.
- Before a saved token is used, PGARD checks it with GitHub (`GET /user`). If the entry is expired, malformed, revoked (GitHub answers 401) or cannot be refreshed, PGARD deletes the entry, says so, and runs the device flow again.
- If no keychain is available (for example a Linux server without a Secret Service), PGARD says why and keeps the sign-in in memory only, for the current CLI process or dashboard session, as before.
- `pgard logout` (or the dashboard's **Sign out and remove from OS keychain**) deletes the entry. It does **not** revoke the token at GitHub: PGARD cannot, because that needs the App's client secret. The token stays valid until it expires (or until it is revoked, if the App does not issue expiring tokens); revoke it at <https://github.com/settings/apps/authorizations> if needed.
- `pgard doctor` shows whether a sign-in is saved and for which account, never the token.
- On macOS the keychain item trusts the `node` binary, so any other Node.js script run by the same user can read it without a prompt.

GitHub App owners can turn token expiry on or off under the App's settings (**Optional features → User-to-server token expiration**). PGARD works either way: with expiry it refreshes, without it the saved token is used until it is revoked.

> **Client id still needed (#42).** The PGARD GitHub App has been registered by the project owner for this repository, but PGARD does not ship a default client id, and whether it will is undecided. Until you set `PGARD_GITHUB_APP_CLIENT_ID`, GitHub identity is `unverifiable` and every real scan is blocked (exit code 3). `pgard doctor` reports whether the variable is set. Owner approval still requires the App to be installed on the personal account that owns the scanned repository.

## Scan scopes and coverage

| Scope     | What it covers                                                        | Selected by                        |
| --------- | --------------------------------------------------------------------- | ---------------------------------- |
| `code`    | Current source code, configuration and dependency advisories          | `scan`, `scan code`, `scan all`    |
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

| Analyzer              | Scope     | Rule ids                                                                                                                           |
| --------------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Source analysis       | `code`    | `PG-SQL-*`, `PG-XSS-*`, `PG-SSRF-*`, `PG-CMD-*`, `PG-PATH-*`, `PG-CRYPTO-*`, `PG-AUTH-*`, `PG-COOKIE-*`, `PG-CSRF-*`, `PG-BRUTE-*` |
| Dependency advisories | `code`    | `PG-DEP-001`                                                                                                                       |
| Git history           | `history` | `PG-SECRET-001` (committed environment file), `PG-SECRET-002` (secret in a tracked file), `PG-SECRET-003` (secret only in history) |
| Local HTTP            | `web`     | `PG-WEB-001` to `PG-WEB-013`                                                                                                       |

Source analysis covers JavaScript, TypeScript, React (JSX/TSX), Vue and Go files. Run `pgard rules list` (optionally with `--language`) for the current list of rules and their severities, instead of relying on a copy in this README.

For the HTML sinks (`innerHTML`, `outerHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`), a value passed straight through a sanitizer call (such as `DOMPurify.sanitize(...)`) is not reported. In JavaScript and TypeScript, a variable also counts as sanitized when PGARD resolves it (with TypeScript's symbol resolution, within the file) to its own `var`/`let`/`const` declaration and every assignment to it is a sanitizer call. Imports, parameters, globals, top-level `var`/`let` of a classic script, and any variable in a file that uses `eval`, `with`, `Function` or string timers are never treated as sanitized. Sanitizers are recognized by function name only; PGARD does not check how the sanitizer is configured.

## Dependency advisories

The `code` scope compares resolved dependency versions with a **local** advisory database in [OSV](https://osv.dev/) format. PGARD never downloads advisory data itself.

```sh
export PGARD_ADVISORY_DB=/path/to/osv-data   # a JSON file or a directory of OSV .json files
```

- Supported inputs: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `go.mod` and `go.sum`.
- Go modules under a `testdata` directory are skipped (they are test fixtures that Go never builds). npm lockfiles there are still checked.
- The file can hold an array of OSV records, or `{ "version", "updatedAt", "vulnerabilities": [...] }`.
- A database larger than 512 MiB (a single file, or the total of a directory) or with more than 500,000 files is `invalid`.
- If the variable is not set, or the data is missing or invalid, the advisory database area is `not_tested`. Data older than 30 days is stale and the area is `partial`. In both cases the `code` scope is incomplete, so `scan`, `scan code` and `scan all` report `partial` with exit code 4.
- Scans always load the database in full. `rules list` and `doctor` only peek: they fully read a file of up to 8 MiB, report a file over 512 MiB as `invalid`, and otherwise check only a sample record (directory) or the first bytes (file). A database that passes only this quick check is shown as `unverified - not fully validated`, without version or freshness, and is a `[warn]` row in `doctor`. A scan can still find it invalid or stale.
- A version match does not show that the vulnerable code is reachable.

How the advisory database is distributed and updated has not been decided yet (#46). There is no update command.

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

Secrets are private keys, well-known token formats (AWS, GitHub, Slack, Stripe, Google API keys) and generic credential assignments (`password = ...`, `api_key: ...`). A generic assignment counts only when its value is a literal that looks random enough and is not a placeholder. In source files, an unquoted value on a line that clearly looks like code (a type, a parameter list, a constant or variable name) is not treated as a credential. Detection is pattern-based and has known gaps (#145).

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

HTML and PDF reports are rendered from the same redacted result. The HTML report is a single file with no scripts and a strict CSP. Reports are written only to the directory you name, never overwrite existing files, and are created with mode `0600`. Keep reports outside the repository so they are not committed by mistake.

## Dashboard

`pgard dashboard` finds the Git root of the current directory, shows it and asks `Start the dashboard for this project? [y/N]`. It needs an interactive terminal; without one it exits with code 2. After you confirm, it starts the local web app and prints a private session URL:

```text
PGARD dashboard is running on 127.0.0.1 only.
Open this private session URL in your browser (valid until you stop the dashboard): http://127.0.0.1:<port>/#token=<random>
```

The dashboard runs its own scans (it never reads CLI results). It shows the authorization checks and the GitHub device code, lets you pick and confirm a local service, select scopes, follow progress, filter findings (test or fixture findings are shown in their own group) and export HTML/PDF reports. It reuses the GitHub sign-in saved in the OS keychain on the server side; the token never reaches the browser. There are two sign-out buttons: **End dashboard session (keep keychain sign-in)** forgets the session in this dashboard only, and the next check reuses the keychain sign-in; **Sign out and remove from OS keychain** also deletes the saved sign-in (for the CLI too). Stop the dashboard with Ctrl+C: its GitHub session ends (the keychain sign-in is kept) and all results are discarded.

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
- The only external network traffic is to GitHub: the device-flow sign-in (and refreshing a saved sign-in) and GitHub API calls that read the metadata needed for authorization (your identity, the app installation, your access and your contributions). To check contribution, PGARD sends the SHAs of local commits to GitHub. `pgard doctor` also checks whether `api.github.com` is reachable.
- After authorization passes, PGARD sends one `GET /` to each discovered listening port on `127.0.0.1` to show its identity. The web checks then send requests only to the service you confirmed.
- Advisory data is read from the local path in `PGARD_ADVISORY_DB`.

## Out of scope for the MVP

- Direct database connections
- Docker or container configuration
- Performance and load testing
- Scanning remote (non-loopback) services
- Attack requests, form submission and other state-changing requests
- Logged-in (authenticated) web browsing (#45). The `web:authenticated` area is always `not_selected`, and PGARD never asks for application passwords.

## Known limitations

- [#42](https://github.com/JadenMeister/pgard/issues/42) The PGARD GitHub App is registered by the owner for this repository, but each user still has to set its client id in `PGARD_GITHUB_APP_CLIENT_ID`; without it every real scan is blocked. Whether PGARD will ship a built-in default is undecided.
- [#43](https://github.com/JadenMeister/pgard/issues/43) Organization repositories are blocked because owner approval cannot be proven.
- [#44](https://github.com/JadenMeister/pgard/issues/44) PDF reports replace text outside Latin-1 (for example Korean) with `?`. Use the HTML report for the full text.
- [#45](https://github.com/JadenMeister/pgard/issues/45) Logged-in web browsing is not available.
- [#46](https://github.com/JadenMeister/pgard/issues/46) How the advisory database is distributed and updated is undecided.
- [#47](https://github.com/JadenMeister/pgard/issues/47) Squash-merged and co-authored contributions are handled conservatively: co-author trailers and unsigned direct pushes do not count as contribution.
- [#143](https://github.com/JadenMeister/pgard/issues/143) Follow-ups from the keychain sign-in review: narrow races between a keychain save and a removal; a session-only dashboard sign-out during a token refresh can make the next use ask for a new device code; and after `pgard login` switches accounts, the dashboard keeps the previous account's port access for up to 30 minutes (scans still re-check authorization).
- [#145](https://github.com/JadenMeister/pgard/issues/145) Secret detection misses some forms, for example template literals, TypeScript type-annotated declarations, Go `:=` declarations, credentials in `postgres://` URLs and index assignments such as `headers["x-api-key"] = "..."`.
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
| `packages/advisory`        | Dependency advisories from local OSV data           |
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

## License

[MIT](LICENSE)
