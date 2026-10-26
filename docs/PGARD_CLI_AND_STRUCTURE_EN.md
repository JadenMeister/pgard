# PGARD CLI and Repository Structure Detailed Specification

> **Note:** This document is the MVP planning record and a translation of the Korean original ([PGARD_CLI_AND_STRUCTURE_KO.md](PGARD_CLI_AND_STRUCTURE_KO.md)), which remains the authoritative record. The current behaviour is described in the [README](../README.md) ([한국어](../README.ko.md)); where they differ, the README is correct.

This document is a detailed appendix to the PGARD integrated brief. The product name `pgard`, local execution, the permission gate of owner approval, current access, and actual contribution, and one-time result handling are confirmed product conditions. The implementation languages TypeScript/Node.js/React and the folder structure below are recommendations.

## 1. CLI Command Hierarchy

| Command                                                  | Role                                                                                                                                                    |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pgard`                                                  | Arrow-key TUI main menu. Choose project verification, scan by scope, dashboard, rules, or diagnostics                                                   |
| `pgard project verify`                                   | Check the current Git repository, GitHub remote, owner approval, current access, and actual contribution item by item, and show the reason for pass/reject/unable to verify |
| `pgard scan`                                             | Default scope: current code, configuration, and dependencies + Git history                                                                              |
| `pgard scan code`                                        | Scan only current code, configuration, and dependencies. The Git lookup used to verify contribution is still performed                                 |
| `pgard scan history`                                     | Scan only secrets and risky files in past Git commits and tracked files                                                                                 |
| `pgard scan web [--port N]`                              | Scan responses, headers, and allowed pages of a local HTTP service connected to the approved project                                                    |
| `pgard scan all [--port N]`                              | Combined scan of code + history + web under the same scan ID                                                                                            |
| `pgard dashboard [--target-port N]`                      | Start a separate local web app. Run new scans in the web UI and show the results of that session                                                       |
| `pgard rules list [--language js\|ts\|react\|vue\|go]`   | Show supported rules, verdict criteria version, vulnerability data version, and unsupported scope                                                       |
| `pgard doctor`                                           | Diagnose Git, runtime environment, GitHub connection, and local port detectability. Not a scan or permission approval                                   |
| `pgard --help`, `pgard <command> --help`, `pgard --version` | Usage and version                                                                                                                                    |

Every `scan` variant and every new scan in the dashboard passes the same permission gate again **each time**. A passing result from an earlier `project verify` is not stored or reused for later commands. `rules list` and `doctor` can be run outside a project. Because GitHub tokens and scan results are not stored between commands, there is no separate persistent login command or command for viewing past results.

### Options and Boundaries

- `--port` is allowed only for `scan web` and `scan all`. `--target-port` is allowed only for `dashboard` and is the **port of the service to scan**. The dashboard itself binds to a separate available loopback port. Only numbers from 1 to 65535 are accepted as ports, and the actual connection is fixed to `127.0.0.1`.
- If the port is omitted, open local HTTP candidates and `Other port` are shown. Even for a specified port, after showing the URL, response status, `<title>`, and inferred technology, an explicit `Y` is required at `Is this the current project's service? [y/N]`. `N` means choosing another port or cancelling. Y/N is the user's selection of a target, not proof of identity.
- Every `scan` variant can accept `--report html|pdf|both --output-dir <path>`. Using only one of the two is a usage error. Reports are saved only to the location the user specifies and never overwrite existing files. If the path is inside a Git repository, a warning about tracking/commit risk is shown and explicit confirmation is required. By default, only terminal results are shown.
- Unknown commands/options, invalid values, and incompatible option combinations are rejected before any authentication, scan, or network call. `--path`, `--host`, `--url`, `--force`, and `--skip-auth` do not exist in the MVP. The CLI scan target is the Git root of the current directory.

### TUI and Results

The order is main menu → project verification → GitHub authentication, permission, and contribution checks → scan scope → for web scope, port and service confirmation → execution progress → choosing results and reports. Subcommands skip the main menu and enter the corresponding flow. Controls are unified as: arrow keys to move, Enter to select, Esc for the previous step (cancel confirmation during execution), `?` for help, and Ctrl+C for cancel confirmation. The CLI does not accept service login passwords, and pages behind a login are examined only when the user logs in directly in a temporary browser session.

Results are shown in this order: severity bar chart, confirmed/suspected, file:line or URL, masked evidence and guidance, coverage. Areas that a standalone scan did not select are marked `not_selected`, areas that were selected but could not be run are marked `not_tested`, and areas that were only partly finished are marked `partial`. `No findings` and `scan failed` are different.

`scan all` means that the supported code/history/web scopes are run together. If there is no web port or it is not confirmed, the combined scan is not marked complete. If the user wants, they can accept the code/history results as partially complete and leave web as `not_tested`. Post-authentication exploration is added only when the user requests it; when not requested, it is `not_selected`. Direct DB connections, Docker, performance, brute force, and state-changing requests are not included.

Exit codes are `0` requested scope completed (even if there are findings), `2` invalid command or option, `3` repository/permission/contribution gate failure, `4` partial scan failure or report save failure, `5` internal error, and `130` user cancellation. On partial failure, the results obtained are shown.

`dashboard` does not automatically read past CLI results. It **explicitly** starts an independent local web app, confirms the current project in the launcher, and runs new scans in the web UI. Results, tokens, and temporary browser sessions are discarded on exit, and only the HTML/PDF exported by the user remains.

## 2. Recommended Repository and File Structure

```text
apps/
  cli/
    package.json
    src/
      bin/pgard.ts              # process entry point
      app.ts                    # command parsing and TUI launch wiring
      options.ts                # option validation and help
      commands/
        project/verify.ts
        scan/index.ts           # code + history
        scan/code.ts
        scan/history.ts
        scan/web.ts
        scan/all.ts
        dashboard.ts            # explicitly starts the independent local web executable
        rules/list.ts
        doctor.ts
      flows/
        authenticate.ts
        select-project.ts
        select-local-port.ts
        run-scan.ts
        export-report.ts
      ui/
        screens/               # AuthScreen, ProjectScreen, ScopeScreen,
                               # PortScreen, ScanScreen, ResultsScreen
        components/            # ChoiceList, ConfirmPrompt, ProgressView,
                               # FindingRow, SeverityBars
        formatters/            # severity, path, and time display
      state/session.ts          # in-memory-only execution state
      adapters/                # terminal, browser, and file-selection boundaries
  local-web/
    package.json
    src/
      server/
        index.ts                # start and stop on 127.0.0.1
        create-server.ts
        launcher.ts             # confirm the current project folder
        middleware/
          local-origin.ts       # Host/Origin/CORS
          session-token.ts      # local API session
          csrf.ts
          no-store.ts
        routes/                 # auth, project, ports, scans, reports
        session/                # in-memory store, project-grant
      client/
        main.tsx
        app/                    # App, providers
        api/client.ts           # local server calls
        features/
          onboarding/          # permission and project
          target/              # port and service confirmation
          scan/                # progress and coverage
          findings/            # filters and details
          reports/             # HTML/PDF
          legal/               # terms of service and privacy notice
        components/
          ui/                  # Button, Modal, Card, Badge, EmptyState
          findings/            # FindingCard, SeverityBadge, LocationLink
          charts/              # SeverityBarChart, SeverityDonutChart
          layout/              # PageShell, Navigation, StatusNotice
        hooks/
        styles/tokens.css
packages/
  scan-core/                   # scan scope, progress, and common result coordination
  policy/                      # permission gate and target restrictions
  github-auth/                 # GitHub login and approval checks
  git-history/                 # remote/SHA/contribution and secret history
  source-analysis/             # JS/TS/React/Vue/Go rules
  http-local/                  # restricted loopback HTTP
  advisory/                    # matching against local vulnerability data
  findings/                    # result schema, masking, and chart aggregation
  report/                      # HTML/PDF rendering
```

`apps/cli` and `apps/local-web` do not import each other's source. `dashboard.ts` starts the installed local web executable without a shell string. `scan-core` and `findings` provide the result and scan semantics common to both apps. Components used by only one screen go next to that feature/screen, and components used by several screens go in each app's `components/`. React components are not shared with the CLI TUI; only data types, masking, and aggregation functions are shared. The browser bundle does not include GitHub tokens, Node file APIs, or the scan engine.

## 3. Code Scan Terminology

- **SQL adapter:** A scan module that recognizes how different SQL libraries such as `pg`, Prisma, and GORM invoke queries. It is not a DB connection feature.
- **AST (abstract syntax tree):** A form that reads code structurally rather than by text search, capturing variables, function calls, and string concatenation.
- **Data flow analysis:** Looks at whether user input went through validation and parameter binding, and traces the path it takes to the SQL execution function. For example, if a request value is concatenated directly into a SQL string, it is flagged for review, and when the evidence is insufficient it is marked `suspected` or `not tested` instead of confirmed.

The first SQL library candidates are `pg`, `mysql2`, Prisma raw query, Go `database/sql`, and GORM. This list is a recommendation and does not declare unsupported ORMs safe.
