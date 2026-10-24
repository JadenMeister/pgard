# ===== ENGLISH =====

## Install and build

Requirements: Node.js 22.12 or newer, Git.

```sh
git clone https://github.com/JadenMeister/pgard.git
cd pgard
npm ci
npm run build          # TypeScript + the dashboard UI (Vite)
npm link -w @pgard/cli # optional: puts `pgard` on your PATH
```

Without `npm link`, run `node apps/cli/dist/bin/pgard.js <command>`.

PGARD verifies your GitHub identity with a registered PGARD GitHub App. Set its client id before scanning:

```sh
export PGARD_GITHUB_APP_CLIENT_ID=<client id of the PGARD GitHub App>
```

> Limitation (#42): no public PGARD GitHub App is registered yet. Until one is configured, the GitHub identity check is "unverifiable" and **every scan is blocked** (exit 3). `pgard doctor` reports this.

## Commands

The target is always the **Git root of the current directory**. Every scan re-runs the authorization gate (owner approval + your current access + a merged contribution); a previous `project verify` is never reused.

| Command                                                     | What it does                                                                                                                                                                   |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `pgard`                                                     | Arrow-key main menu (verify, scans, dashboard, rules, doctor, quit)                                                                                                            |
| `pgard project verify`                                      | Runs the authorization gate and shows each check (repository, GitHub identity, owner approval, current access, contribution) as passed / failed / unverifiable with its reason |
| `pgard scan`                                                | Code, configuration, dependencies + Git history                                                                                                                                |
| `pgard scan code`                                           | Current code, configuration and dependencies                                                                                                                                   |
| `pgard scan history`                                        | Git history and tracked files (secrets, risky files)                                                                                                                           |
| `pgard scan web [--port N]`                                 | Anonymous, read-only checks of a local HTTP service you confirm                                                                                                                |
| `pgard scan all [--port N]`                                 | code + history + web                                                                                                                                                           |
| `pgard dashboard [--target-port N]`                         | Starts the local web dashboard                                                                                                                                                 |
| `pgard rules list [--language js\|ts\|react\|vue\|go]`      | Supported rules, criteria/advisory data version, unsupported areas (works outside a project)                                                                                   |
| `pgard doctor`                                              | Diagnoses Node.js, Git, GitHub reachability, port discovery, `PGARD_GITHUB_APP_CLIENT_ID`, advisory DB. Diagnosis only, not an authorization (works outside a project)         |
| `pgard --help`, `pgard <command> --help`, `pgard --version` | Usage and version                                                                                                                                                              |

Options:

- `--port N` (only `scan web` / `scan all`): local service port, integer 1–65535. You still confirm the service with `y`.
- `--target-port N` (only `dashboard`): pre-selects the service to check in the dashboard (still confirmed there). The dashboard itself uses its own free port.
- `--report html|pdf|both --output-dir <dir>` (any `scan`): must be used together. The directory must already exist. Files are never overwritten. A directory inside the Git repository requires an explicit `y` (without a terminal this is refused). By default only the terminal result is shown.
- Unknown commands/options, invalid values and wrong combinations are rejected **before** any Git, GitHub or network activity. There is no `--path`, `--host`, `--url`, `--force` or `--skip-auth`.

Exit codes:

| Code | Meaning                                                                                          |
| ---- | ------------------------------------------------------------------------------------------------ |
| 0    | Requested scope completed (findings may exist); `doctor` completed its diagnosis                 |
| 2    | Invalid command, option, value or combination                                                    |
| 3    | Repository / authorization / contribution gate failed (or not inside a Git repository)           |
| 4    | Part of the scan did not run (e.g. web not confirmed ⇒ partial) or the report could not be saved |
| 5    | Internal error (details hidden; `PGARD_DEBUG=1` shows a sanitized message)                       |
| 130  | Cancelled by the user                                                                            |

## Interactive keys

Arrow keys (or j/k) move, Enter selects, Esc goes back (inside the menu, Esc on a sub-step returns to the menu), `?` shows help, Ctrl+C asks "Cancel and exit? [y/N]". While a scan or GitHub sign-in is running, press Ctrl+C twice within 5 seconds to cancel (exit 130). Keys typed while a scan runs are discarded so they cannot answer the next prompt.

## GitHub sign-in

When needed, PGARD shows the GitHub device-flow URL (`https://github.com/login/device`) and a short user code. The access token stays in memory for the current process only and is never printed, logged or stored.

## Local web target confirmation

For `scan web`, `scan all` and the dashboard:

1. PGARD verifies authorization before touching any port.
2. It lists listening ports that answer HTTP on `127.0.0.1` (via `lsof` on macOS, `/proc/net/tcp*` on Linux). The list can be incomplete — **Other port** is always offered. A port number alone says nothing about which project it belongs to.
3. It shows the service identity: URL, HTTP status, `<title>`, and inferred technology (from headers/markup — a guess, not verified).
4. You answer **"Is this the current project's service? [y/N]"**. Only an explicit `y` confirms; Enter, `n` and Esc mean no (choose another port or continue without web checks). `--port` still requires this confirmation.
5. Without an interactive terminal the target cannot be confirmed: web is recorded as **not tested** and the scan is **partial** (exit 4).

Web checks use anonymous GET/HEAD requests to `127.0.0.1:<port>` only: redirects are followed only on the same loopback origin; links that look like logout/delete/reset actions are skipped; limits are 20 pages, depth 2, 5 s per request, 60 s total, 1 MB per body; query strings are never reported. Checks: security headers (CSP, frame protection, nosniff, Referrer-Policy; HSTS is not applicable on plain-http loopback), cookie flags, CORS wildcard/reflection with credentials, server version disclosure, directory listing, served `/.env` and `/.git/HEAD` (presence only, never values). A missing header is informational, never proof of a vulnerability. GET requests can still change state in a badly built application; PGARD does not guarantee side-effect-free checks.

## Results and reports

The terminal result shows a severity bar chart, confirmed / suspected / informational findings with `file:line` or URL, redacted evidence and guidance, and coverage (`completed`, `partial`, `not_tested`, `not_selected`). "No findings" is never shown as "secure".

HTML and PDF reports are rendered from the same redacted result. HTML is self-contained (no scripts, strict CSP, everything escaped). Files are written only to the directory you named, with exclusive create (never overwriting, mode 0600). Store reports outside the repository.

> Limitation (#44): the PDF uses built-in Latin fonts; non-Latin text (e.g. Korean) is replaced with `?` and the PDF says so. Use the HTML report for full text.

## Dashboard (`pgard dashboard`)

`pgard dashboard` confirms the project (Git root of the current directory) in the terminal, then starts the local web app and prints a private session URL:

```
PGARD dashboard is running on 127.0.0.1 only.
Open this private session URL in your browser (valid until you stop the dashboard): http://127.0.0.1:<port>/#token=<random>
```

The dashboard runs its own scans (it never reads CLI results): authorization status with per-check reasons and the GitHub device code, local service selection with identity + explicit confirmation, scope selection with progress/cancel and coverage, findings with severity bar and donut charts and filters, and HTML/PDF export (absolute existing directory, inside-repository confirmation, no overwrite). Stop it with Ctrl+C: the GitHub session is signed out and all results are discarded.

Security model:

- Binds to `127.0.0.1` only, on a free port.
- A random 32-byte session token travels in the URL **fragment** (never sent in requests or Referer). The page removes it from the address bar and keeps it in memory. Do not share the URL.
- Every API call needs the token in a custom header (`x-pgard-token`), which also blocks CSRF; the exact `Host: 127.0.0.1:<port>` is required (DNS rebinding protection); foreign `Origin` and cross-site requests are refused; no CORS headers are ever sent.
- Every response has `Cache-Control: no-store`, a strict Content-Security-Policy (no inline scripts), `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`.
- The browser cannot choose files or folders: the project root is fixed by the launcher, there is no file-reading API, and only built UI assets are served. The browser receives redacted findings only — never source code, the GitHub token or the scan engine.

Privacy notice (shown once in the dashboard): scan data is processed once, on your computer; PGARD contacts GitHub for sign-in and repository metadata (and the network for advisory updates you start); results, token and sign-in are discarded on exit; only reports you export remain and you are responsible for them; GET requests can still have side effects in some applications.

## Limitations

- #42 No registered PGARD GitHub App yet ⇒ GitHub identity is unverifiable and every scan is blocked.
- #45 Authenticated (logged-in) browsing is not available in this MVP; `web:authenticated` is always `not_selected`. PGARD never asks for application passwords.
- #44 PDF reports replace non-Latin characters; use HTML for full text.
- Port discovery can be incomplete or unavailable (e.g. when `lsof` hangs, it gives up after 5 s); enter the port manually.
- Not in scope: database connections, Docker, performance testing, remote (non-loopback) services, form submission / state-changing requests.
