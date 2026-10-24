# PGARD

English | [한국어](README.ko.md)

PGARD (`pgard`) is a local security scanner for GitHub projects you are authorized to scan. It runs on your own computer as a command-line tool and a local web dashboard. It checks the current code, configuration and dependencies, the Git history, and (optionally) a web service you run on `127.0.0.1`.

Before every scan, PGARD checks that the repository owner approved PGARD, that you currently have access to the repository, and that you really contributed to it. Your code and the results stay on your computer.

PGARD is an MVP. It does not find every vulnerability, and "no findings" never means "secure".

> **Current status:** no PGARD GitHub App is registered yet, so real scans are blocked until one is configured (see [GitHub App and sign-in](#github-app-and-sign-in) and #42).

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
pgard project verify  # check authorization only
pgard scan            # code + history
```

## Commands

The target is always the **Git root of the current directory**. There is no option to choose another path, host or URL, and no option to skip authorization. Every scan runs the authorization checks again; an earlier `project verify` is never reused.

`pgard --help` prints:

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
  pgard --help | <command> --help
  pgard --version
```

| Command                | What it does                                                                                                                                                                                                   |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pgard`                | Interactive menu: verify, scans, dashboard, rules, doctor, quit.                                                                                                                                               |
| `pgard project verify` | Runs the authorization checks and shows each one (repository, GitHub identity, owner approval, current access, contribution) as passed, failed or unverifiable, with a reason. The result is not stored.       |
| `pgard scan`           | `code` + `history`.                                                                                                                                                                                            |
| `pgard scan code`      | Current source code, configuration and dependency advisories.                                                                                                                                                  |
| `pgard scan history`   | Committed `.env` files and secrets in tracked files and Git history.                                                                                                                                           |
| `pgard scan web`       | Anonymous, read-only checks of a local HTTP service on `127.0.0.1` that you confirm.                                                                                                                           |
| `pgard scan all`       | `code` + `history` + `web`. If no web target is confirmed, the result is `partial`.                                                                                                                            |
| `pgard dashboard`      | Starts the local web dashboard. See [Dashboard](#dashboard).                                                                                                                                                   |
| `pgard rules list`     | Lists the supported rules, the detection criteria and advisory data versions, and the areas PGARD does not cover. Works outside a project and makes no network requests.                                       |
| `pgard doctor`         | Checks Node.js, Git, GitHub reachability, local port discovery, whether `PGARD_GITHUB_APP_CLIENT_ID` is set, and the advisory database. It is a diagnosis only, not an authorization. Works outside a project. |

The exact output of `pgard rules list` and `pgard doctor` is still changing (#112), so it is not copied here.

### Options

- `--port N` (`scan web` and `scan all` only): the local service port, an integer from 1 to 65535. You still have to confirm the service.
- `--target-port N` (`dashboard` only): pre-selects the local service to check. You still confirm it in the browser. The dashboard itself runs on its own free port.
- `--report html|pdf|both` and `--output-dir <dir>` (any `scan`): save a report. The two options must be used together. The directory must already exist, and existing files are never overwritten. A directory inside the Git repository needs an explicit `y` (without an interactive terminal it is refused). By default, results are only shown in the terminal.
- `--language js|ts|react|vue|go` (`rules list` only): filter the rule list by language.
- `--help` / `-h`, and `pgard --version` / `-V`.

Unknown commands and options, invalid values and invalid combinations are rejected before any Git, GitHub or network activity.

### Exit codes

| Code | Meaning                                                                                                                         |
| ---- | ------------------------------------------------------------------------------------------------------------------------------- |
| 0    | The requested scope completed (findings may exist). For `doctor`: the diagnosis completed.                                      |
| 2    | Invalid command, option, value or combination.                                                                                  |
| 3    | The repository, authorization or contribution check failed (the scan was blocked).                                              |
| 4    | Part of the scan did not run (for example, no web target was confirmed, so the result is partial), or the report export failed. |
| 5    | Internal error. Details are hidden; set `PGARD_DEBUG=1` to see a sanitized message.                                             |
| 130  | Cancelled by the user.                                                                                                          |

### Interactive keys

Arrow keys (or `j`/`k`) move, Enter selects, Esc goes back, and `?` shows help. Ctrl+C asks `Cancel and exit? [y/N]`. While a scan or GitHub sign-in is running, press Ctrl+C twice within 5 seconds to cancel (exit code 130).

## Authorization model

PGARD scans a repository only when it has evidence that you are allowed to. Before every scan it checks, in order:

1. **Repository.** The current directory is the root of a Git repository with valid history. The repository uses only its own objects and history (no alternates, grafts or replace refs), and it has exactly one unambiguous `github.com` remote.
2. **GitHub identity.** You sign in to GitHub with the device flow (see below).
3. **Owner approval.** The PGARD GitHub App is installed on the repository owner's **personal account**, and that installation includes this repository. Only the owner of a personal account can install an app on it.
4. **Current access.** GitHub reports that you currently have at least read access to the repository.
5. **Contribution.** Your contribution is in the default-branch history. A commit counts only if GitHub shows it in the default branch, and either it belongs to a pull request you authored that was merged into the default branch, or GitHub verified its signature and attributes the committer to you. Author names or emails, co-author trailers, unmerged pull requests, pull requests merged into other branches or forks, unsigned direct pushes and local-only commits are never accepted as proof.

Each check is `passed`, `failed` or `unverifiable`, with a reason. The scan runs only if every check passed. If any evidence is missing or unclear, the scan is **blocked** (exit code 3) and PGARD reports which check failed and why.

### Organization repositories

Repositories owned by an organization are always blocked (#43). GitHub's APIs cannot prove that an organization owner, rather than a repository admin, installed the PGARD GitHub App, so owner approval is reported as `unverifiable`.

### GitHub App and sign-in

PGARD signs you in through a GitHub App using the OAuth device flow. It needs the app's public client id:

```sh
export PGARD_GITHUB_APP_CLIENT_ID=<client id of the PGARD GitHub App>
```

When sign-in is needed, PGARD shows the URL `https://github.com/login/device` and a short user code. You open the URL, enter the code and approve. PGARD keeps the access token **in memory only**, for the current CLI process or dashboard session. It is never printed, logged or written to disk, and it is dropped on exit or sign-out.

> **No PGARD GitHub App is registered yet (#42).** Until a client id is configured, GitHub identity is `unverifiable` and every real scan is blocked (exit code 3). `pgard doctor` reports whether the variable is set.

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

`scan all` (and `scan web`) report `partial` with exit code 4 when no web target is confirmed, for example when you answer no or when there is no interactive terminal. The `web` scope is then `not_tested`.

## Analyzers and rules

| Analyzer              | Scope     | Rule ids                                                                                                                           |
| --------------------- | --------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Source analysis       | `code`    | `PG-SQL-*`, `PG-XSS-*`, `PG-SSRF-*`, `PG-CMD-*`, `PG-PATH-*`, `PG-CRYPTO-*`, `PG-AUTH-*`, `PG-COOKIE-*`, `PG-CSRF-*`, `PG-BRUTE-*` |
| Dependency advisories | `code`    | `PG-DEP-001`                                                                                                                       |
| Git history           | `history` | `PG-SECRET-001` (committed environment file), `PG-SECRET-002` (secret in a tracked file), `PG-SECRET-003` (secret only in history) |
| Local HTTP            | `web`     | `PG-WEB-001` to `PG-WEB-013`                                                                                                       |

Source analysis covers JavaScript, TypeScript, React (JSX/TSX), Vue and Go files. Run `pgard rules list` (optionally with `--language`) for the current list of rules and their severities, instead of relying on a copy in this README.

## Dependency advisories

The `code` scope compares resolved dependency versions with a **local** advisory database in [OSV](https://osv.dev/) format. PGARD never downloads advisory data itself.

```sh
export PGARD_ADVISORY_DB=/path/to/osv-data   # a JSON file or a directory of OSV .json files
```

- Supported inputs: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `go.mod` and `go.sum`.
- The file can hold an array of OSV records, or `{ "version", "updatedAt", "vulnerabilities": [...] }`.
- If the variable is not set, or the data is missing or invalid, dependency advisories are reported as `not_tested`. Data older than 30 days is reported as stale.
- A version match does not show that the vulnerable code is reachable.

How the advisory database is distributed and updated has not been decided yet (#46). There is no update command.

## Local web checks

`scan web`, `scan all` and the dashboard check a web service only after you confirm it:

1. PGARD checks authorization before it touches any port.
2. It lists listening ports that answer HTTP on `127.0.0.1`. The list can be incomplete, so **Other port** is always offered. A port number alone says nothing about which project it belongs to.
3. It shows the service's URL, HTTP status, page title and guessed technology.
4. You answer `Is this the current project's service? [y/N]`. Only an explicit `y` confirms. `--port` still requires this confirmation.
5. Without an interactive terminal the target cannot be confirmed, so `web` is `not_tested` and the scan is `partial` (exit code 4).

The checks send only anonymous `GET`/`HEAD` requests to `127.0.0.1:<port>`. Redirects are followed only on the same loopback origin, and links that look like logout, delete or reset actions are skipped. Limits: 20 pages, depth 2, 5 seconds per request, 60 seconds in total and 1 MB per response body. They look at security headers, cookie flags, CORS with credentials, server version disclosure, directory listing, and whether `/.env` or `/.git` is served (presence only, values are never kept). A missing header is reported as informational, not as proof of a vulnerability.

A badly built application can still change state on a `GET` request. PGARD cannot guarantee that the checks have no side effects.

## Results and reports

The terminal result shows a severity chart, the findings (confirmed, suspected or informational) with a `file:line` or URL, redacted evidence, guidance, and the coverage of each area.

HTML and PDF reports are rendered from the same redacted result. The HTML report is a single file with no scripts and a strict CSP. Reports are written only to the directory you name, never overwrite existing files, and are created with mode `0600`. Keep reports outside the repository so they are not committed by mistake.

## Dashboard

`pgard dashboard` checks the project in the terminal, starts the local web app and prints a private session URL:

```text
PGARD dashboard is running on 127.0.0.1 only.
Open this private session URL in your browser (valid until you stop the dashboard): http://127.0.0.1:<port>/#token=<random>
```

The dashboard runs its own scans (it never reads CLI results). It shows the authorization checks and the GitHub device code, lets you pick and confirm a local service, select scopes, follow progress, filter findings and export HTML/PDF reports. Stop it with Ctrl+C: the GitHub session is signed out and all results are discarded.

How the dashboard protects itself:

- It binds to `127.0.0.1` only, on a free port.
- A random 32-byte session token is passed in the URL **fragment**, so the browser never sends it in requests or `Referer` headers. The page removes it from the address bar and keeps it in memory. Do not share the URL.
- Every API call must carry the token in the `x-pgard-token` header. The `Host` header must be exactly `127.0.0.1:<port>` (DNS rebinding protection). Requests from another `Origin` and cross-site requests are refused, and no CORS headers are sent.
- Every response has `Cache-Control: no-store`, a strict Content-Security-Policy, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.
- The browser cannot choose files or folders. The project root is fixed when the dashboard starts, and the browser receives only redacted findings, never source code or the GitHub token.

## Privacy and network traffic

- Your code, Git history and scan results are processed on your computer and are not uploaded anywhere. Results are kept in memory and discarded when the process or dashboard stops; only reports you export are saved.
- The only external network traffic is to GitHub: the device-flow sign-in and GitHub API calls that read the metadata needed for authorization (your identity, the app installation, your access and your contributions). `pgard doctor` also checks whether `api.github.com` is reachable.
- Web checks send HTTP requests only to the service you confirmed on `127.0.0.1`.
- Advisory data is read from the local path in `PGARD_ADVISORY_DB`.

## Out of scope for the MVP

- Direct database connections
- Docker or container configuration
- Performance and load testing
- Scanning remote (non-loopback) services
- Attack requests, form submission and other state-changing requests
- Logged-in (authenticated) web browsing (#45). The `web:authenticated` area is always `not_selected`, and PGARD never asks for application passwords.

## Known limitations

- [#42](https://github.com/JadenMeister/pgard/issues/42) No PGARD GitHub App is registered yet, so every real scan is blocked.
- [#43](https://github.com/JadenMeister/pgard/issues/43) Organization repositories are blocked because owner approval cannot be proven.
- [#44](https://github.com/JadenMeister/pgard/issues/44) PDF reports replace text outside Latin-1 (for example Korean) with `?`. Use the HTML report for the full text.
- [#45](https://github.com/JadenMeister/pgard/issues/45) Logged-in web browsing is not available.
- [#46](https://github.com/JadenMeister/pgard/issues/46) How the advisory database is distributed and updated is undecided.
- [#47](https://github.com/JadenMeister/pgard/issues/47) Squash-merged and co-authored contributions are handled conservatively: co-author trailers and unsigned direct pushes do not count as contribution.
- [#108](https://github.com/JadenMeister/pgard/issues/108) In very large histories, a `.env` file whose current state is unknown, or a secret moved to another file, can be reported as removed.
- [#115](https://github.com/JadenMeister/pgard/issues/115) Some dependency inputs are reported as `completed` too optimistically (unvalidated advisory directories, non-registry pnpm entries, Go modules with both `go.mod` and `go.sum`), and Yarn Berry patch entries make many projects `partial`.
- [#117](https://github.com/JadenMeister/pgard/issues/117) Test files are not type-checked yet.
- Detection is not complete. Missing findings do not mean the project is secure.
- Port discovery can be incomplete or unavailable. Type the port by hand in that case.

## Development

This is an npm workspaces monorepo written in TypeScript.

| Path                       | Contents                                      |
| -------------------------- | --------------------------------------------- |
| `apps/cli`                 | The `pgard` command-line tool                 |
| `apps/local-web`           | The local web dashboard (server and React UI) |
| `packages/policy`          | Authorization checks                          |
| `packages/github-auth`     | GitHub device flow and API client             |
| `packages/scan-core`       | Scan orchestration, scopes and coverage       |
| `packages/source-analysis` | Source code rules                             |
| `packages/advisory`        | Dependency advisories from local OSV data     |
| `packages/git-history`     | Git history and secret scanning               |
| `packages/http-local`      | Local HTTP checks and port discovery          |
| `packages/findings`        | Shared finding and coverage types, redaction  |
| `packages/report`          | HTML and PDF reports                          |
| `tests/integration`        | Cross-package integration tests               |

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
