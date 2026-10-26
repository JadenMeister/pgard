# PGARD — Integrated Brief for Implementation Agents

> **Note:** This document is the MVP planning record and a translation of the Korean original ([PGARD_AGENT_BRIEF_KO.md](PGARD_AGENT_BRIEF_KO.md)), which remains the authoritative record. The current behaviour is described in the [README](../README.md) ([한국어](../README.ko.md)); where they differ, the README is correct.

**Current status:** The product name and default command `pgard`, local execution, GitHub owner approval, current-access and actually-merged-contribution checks, and the scope of code/Git/local HTTP scanning were decided in conversation. The TypeScript/Node.js/React implementation stack is a recommendation. The current document workspace has no Git repository and no PRs awaiting review, so no implementation, PR creation, or merge was performed.

## Detailed documents every implementation owner should read

- [CLI command system and app/package file structure](PGARD_CLI_AND_STRUCTURE_EN.md): `project verify`, per-scope `scan`, the combined scan, the dashboard, rules, diagnostics, and component reuse boundaries.
- [Implementation, commit, and code conventions](PGARD_DEVELOPMENT_CONVENTIONS_EN.md): commit granularity, messages, naming, verification, and PR responsibilities.

Where command, directory, or result-scope notation in the draft below differs from the detailed documents above, **the latest rules in the detailed documents take precedence**. For permissions, privacy, and MVP exclusions, follow the conditions in the product specification and technical structure below as written.

## Product Specification

This document separates **product requirements confirmed in conversation**, **implementation choices that were only proposed**, and **undecided items**. Future implementation agents must not turn proposals into confirmed decisions.

### 1. Product definition

PGARD (Project Guard) is a local-first open-source security tool that inspects the code and Git history of a project the user has contributed to and been granted permission to scan, together with local web services the user connects, and provides evidence of vulnerabilities and remediation guidance. The name and the CLI command are confirmed as `pgard`. It builds an independent CLI and web product, but the meaning of scan results must be consistent across both. It ships under the MIT license with Korean and English READMEs. The web product's terms of service / privacy notice must state **one-time local processing**, external communication for GitHub authentication and optional vulnerability data updates, and **that only reports the user explicitly exports are left at a user-specified location**. Purchasing a paid domain is on hold.

#### Status summary

| Area        | Confirmed                                                                                              | Recommended / design assumption                                                                                     | Undecided                                                                  |
| ----------- | ------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Execution   | CLI and web are separate, both run locally                                                             | Both frontends share a local scan engine                                                                            | Distribution packaging and installation method                             |
| Languages   | First scan targets are JS/TS, React, Vue, Go                                                           | TypeScript as the main development language, Node.js runtime, React web UI, Go syntax-analysis adapter              | Final approval and version pinning of implementation language / frameworks |
| Permissions | Per-repository owner approval of the GitHub App + user login + current access + verified contribution | Match Git log candidates against GitHub history                                                                     | Exact implementation of owner-approval evidence; squash / co-author handling |
| Code scan   | JS/TS, React, Vue, Go and the vulnerability categories below                                           | Support commonly used SQL libraries first and verify paths where external input reaches query execution             | Exact detection conditions and coverage per rule                           |
| HTTP scan   | Local port selection, public response/header checks, optional login mode                               | Safe read-only exploration and session isolation                                                                    | Page-exploration limits and session implementation                         |
| Results     | Confirmed / suspected / not-tested distinction, location, evidence, remediation guidance, HTML/PDF     | Common result schema                                                                                                | Severity formula, secret-masking rules                                     |
| Exclusions  | Direct DB connection, Docker configuration, performance analysis                                       | Consider in a later, separate version                                                                               | N/A                                                                        |

### 2. Approval and scan targets

1. The local project directory is a Git repository with valid history. Its relationship to the remote GitHub repository is verified.
2. The user logs in with their own GitHub account. The PGARD GitHub App must be installed on the target repository and requires **approval from the repository owner**. For a personal repository only that individual owner's approval counts; for an organization repository only an organization owner's approval counts. Installation by an administrator or member alone does not satisfy this.
3. The scanning user must have **current access** to the target repository.
4. There must be a commit, contribution, or merge in which the user's own changes were actually reflected in the repository's real history. Opening, reviewing, or commenting on a PR alone does not pass. The author name/email in the Git log alone does not authenticate the user. Commit candidates are found in the local `git log`, and the GitHub account is matched against the repository's commit and merge history.
5. No feature is built to scan other people's deployed services or open-source projects arbitrarily. Local web scanning is likewise limited to approved projects and services the user has connected.

**Undecided / caution:** Whether a GitHub App installation can always prove that "the owner definitely approved" must be verified against GitHub's actual permission model during implementation. If it cannot be verified, do not work around it to let the scan through; design a procedure for owner-approval evidence instead. Detailed rules for linking changed contributions to an account in co-authored commits and squash merges must also be decided. OAuth login is a means of user authentication and does not by itself imply repository-owner approval.

### 3. CLI experience

- A single word, `pgard`, starts the TUI.
- Arrow keys select items, Enter confirms, and Esc returns to the previous step. Text/number input is collected step by step.
- It scans the project and, if desired, also connects a local web service.
- If local web scanning is chosen, candidate open local ports are shown. If the target is not in the list, enter the port number directly under **Other port**.
- It connects to the selected port over HTTP, shows identifying information such as the `<title>`, response status, and inferred technology, then asks "Is this the current project's service? [y/N]". `Y` is the user's choice of target and does not cryptographically prove that the code and the service are the same.
- CLI results provide a per-severity bar chart, a vulnerability/suspected distinction, file:line or URL, evidence, and remediation guidance.

An open port alone does not mean a web service or source code can be accessed. **Code is read from the selected project directory**, and HTTP responses are read **from the confirmed port**. Neither the protocol nor the technology is determined from the port number alone.

### 4. Web product experience

- The web product also runs on the user's computer. It does not use an architecture in which a hosted server connects directly to the user's `127.0.0.1`.
- It has a user interface separate from the CLI, and scan results are shown in a dashboard with bar/donut charts together with URL/file locations.
- The core of web scanning is code analysis. A running HTTP service is verified as a supplement, centered on its responses and security headers.
- Code scanning and unauthenticated HTTP scanning work without logging in. If post-login scanning is chosen, the user logs in directly in a browser opened by PGARD. PGARD does not collect the app's login password on the user's behalf. The session is used only for that scan and is discarded when it ends.
- The first version **does not automatically execute known state-changing actions** such as form submission, profile edits, or uploads. However, because even GET exploration can have side effects in a poorly implemented service, this is not described as a complete no-change guarantee. Any part of the unauthenticated/authenticated pages that could not be scanned is marked "not tested" in the results.
- HTTP scanning checks the URLs and headers that can actually be explored, but does not claim to detect every vulnerability completely.

**Undecided:** Crawl depth, URL count/time limits, how authenticated sessions are kept and discarded, and the exact policy for redirects and local address ranges.

### 5. Code, Git, and dependency scan scope

The first supported languages/ecosystems are JavaScript, TypeScript, React, Vue, and Go. React and Vue each get framework-specific rules within JS/TS. The scan goals already discussed are as follows.

| Category                    | Static evidence to check first                                                                                   | Caution in judgement                                                          |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| SQL Injection               | Whether user input is concatenated/interpolated into an SQL string and flows to an execution function; whether parameter binding is used | Does not connect directly to the DB                                           |
| XSS                         | Dangerous HTML output paths and untrusted input flows                                                            | Never confirm a vulnerability from API usage alone                            |
| SSRF                        | Paths where a URL built from external input is passed to a server-side HTTP request                              | Also judge defenses such as allow lists                                       |
| Access control / auth failures | Authentication/authorization checks and session settings on protected routes                                  | If the service's intent is unclear, mark as suspected / needs review          |
| Brute-force defense         | Attempt limits and protections on login and reset features                                                       | Does not perform bulk password guessing                                       |
| Cryptographic failures      | Plaintext password storage, dangerous hashing/encryption, hardcoded keys                                         | Do not expose the values themselves in results                                |
| Misconfiguration / CSRF     | Server configuration, headers, CSRF defense on state-changing requests that use cookie authentication            | Indicate dependence on the deployment environment                             |
| File upload / download      | File type/path handling, permission checks, path-manipulation risk                                               | Does not automatically execute modifying or deleting requests                 |
| Command execution / file paths | Input values passed to a shell or file path                                                                   | Distinguish confirmed flows from simple patterns                              |
| Known CVEs                  | Compare actually locked dependency versions against vulnerable versions                                          | Distinguish a CVE match from actual exploitability                            |
| Git secrets                 | `.env`, passwords, API keys, etc. in currently tracked files and past commits                                    | A `.env` that exists only locally and is excluded from Git is not itself a Git leak |

For the first SQL-related adapters, **`pg`/`mysql2`, Prisma raw query, Go `database/sql`, and GORM** are recommended. This is an implementation scope proposal not yet approved by the user. The exact function list and detection conditions for each library will be refined in the rule specification. Unsupported ORMs are marked "unsupported". CVE data is, in principle, matched locally; the update/distribution method is an implementation choice. Technology-stack detection distinguishes confirmed technology / inferred technology / unverified version, and detection itself is not treated as a vulnerability.

### 6. Results and data handling

- All results are shown with the same evidence and verdicts in the CLI and the web: finding, severity, confirmed/suspected/not tested, file:line or URL, evidence, remediation guidance.
- The user can export results as HTML/PDF. The user manages exported files.
- Scanned code, Git records, secrets, and results are not stored in or sent to any external DB or server of PGARD. Transient information during local execution is minimized. GitHub authentication/permission and history checks require communication with GitHub, so "100% local" is described precisely as **locality of code analysis and result processing**.
- Raw passwords and tokens are not shown on screen, in logs, or in reports. Sensitive values are masked, leaving only the information needed to act, such as location and kind.
- The severity formula, the confirmed/suspected criteria, the disposal of temporary files, logs, and sessions, and the vulnerability data update method are to be written as **implementation specifications within the confirmed product scope**.

### 7. MVP exclusions and later consideration

The MVP excludes entering DB connection information and scanning a DB directly, Docker configuration checks, and performance-leak checks. Checking a web port is different from scanning a DB port. Arbitrary scanning of remote services and aggressive HTTP tests that change state are also left out of the first version. When the scope changes later, the owner-permission and local-processing principles must be reviewed again.

### 8. Deliverables for the next step

1. Detailed design of the permission decision: GitHub App permissions/installation/owner-approval evidence, and exceptions in commit-contribution decisions.
2. Rule lists for each language and framework: source/sink/sanitizer, basis for judgement, suspicion conditions, unsupported scope.
3. CLI and web screen flows and the common result schema.
4. Boundaries and resource limits of local HTTP exploration and authentication mode.
5. Data handling / logging / report-masking policy and distribution method.

---

## Technical and Development Structure

> A **recommended architecture** to hand to agents together with the product specification. It turns agreements such as the scan targets JS/TS, React, Vue, Go and local execution into implementation boundaries, data contracts, and verification conditions. The TypeScript/Node/React implementation stack, the package structure, and the first SQL adapters are proposals before user confirmation, and require approval and compatibility checks at kickoff.

### 1. Technology choices and execution boundaries

- **Recommended main language:** TypeScript / Node.js. The CLI TUI, the local web backend, the shared scan engine, and the report generator are written in the same language.
- **Recommended web UI:** TypeScript + React. It is a separate executable from the CLI, but shares scan rules, the result schema, and the permission gate.
- **Scan target languages:** JavaScript, TypeScript, React JSX/TSX, Vue single-file components, Go. PGARD itself does not need to be written in Go to analyze Go. Start with a syntax-analysis adapter for Go; rules that truly need type information can later be split into a standalone Go analyzer.
- **Execution location:** Code parsing, Git history reading, local HTTP requests, result generation, and PDF/HTML generation are performed on the user's device. Source code and full results are not sent to a PGARD server or external DB.
- **Required external communication:** External requests that PGARD itself initiates are limited to GitHub user authentication, repository access/contribution metadata lookups, and user-initiated vulnerability data updates. The external authentication flow of a web service the user logs in to may occur separately. Therefore it is not described as a "fully offline product"; it means that scan execution and scan data processing are local. Reports record the vulnerability DB version used and its update time.
- **MVP exclusions:** Direct DB connection, performance scanning, Docker configuration scanning, remote web service scanning, brute-force password guessing, destructive dynamic testing.

### 2. Recommended repository/package boundaries

```text
apps/
  cli/                 # pgard entry point, arrow-key TUI, run status/summary display
  local-web/           # separate local entry point and React UI
packages/
  scan-core/           # ScanRequest → ScanResult orchestration, scan scope recording
  policy/              # permission gate, scan target restrictions, result grade criteria
  github-auth/         # GitHub App user login, installation/access/approval checks
  git-history/         # remote/SHA verification, Git history and tracked file scanning
  source-analysis/     # JS/TS/JSX/Vue/Go parsers and rule adapters
  http-local/          # open local port candidates, restricted HTTP scanning
  advisory/            # local vulnerability DB, lockfile/module version matching
  findings/            # common JSON schema, deduplication, masking
  report/              # common results → HTML/PDF output
```

- `apps/*` do not duplicate scan logic and only call `scan-core`. Scanning must be runnable independently of any UI.
- `policy` decides approval and allowed target addresses before a scan starts. No individual scanner bypasses the permission decision on its own.
- Analysis adapters return `Finding[]` and `Coverage[]`. Unsupported technologies or insufficient permissions are expressed as `not tested` and are not treated as `safe`.
- Project files are opened read-only. Project configuration, scripts, dependency installation, and builds are not executed. Git is invoked with fixed arguments, and user input is never assembled into a shell string.

### 3. Scan flow

1. The user selects a project directory. Whether it is a Git repository, the GitHub repository identifier of the `remote`, and the working tree state are checked. Other hosts or ambiguous remotes are not allowed automatically.
2. The account ID is obtained through user authentication suited to a local app, such as the GitHub App **device flow**. The token is kept in memory during execution and is not written to the screen, logs, or reports. If long-term storage is needed, an OS secure store and an explicit logout design must be approved separately. [GitHub CLI and GitHub App guide](https://docs.github.com/en/apps/creating-github-apps/writing-code-for-a-github-app/building-a-cli-with-a-github-app)
3. It is checked whether the repository is a target of the app installation and whether the user currently has repository access. `policy` passes the scan only when **explicit evidence of repository-owner approval** is also met. For an organization repository only organization-owner approval counts. If approval evidence cannot be obtained, no scan is performed.
4. Commit candidates containing changes are found in the local `git log`, and their SHAs are matched against the actual history of the GitHub repository. Commits linked to the GitHub account, co-authorship, and actually merged merge/squash contributions are verified according to policy. A scan is not passed on PR creation, review, or comments alone, nor on a matching author name/email alone. Ambiguous squash contributions are conservatively treated as `unverifiable`.
5. Files and Git history are scanned. It finds vulnerabilities in the current code, hardcoded secrets, and `.env`/secrets committed to Git. A `.env` that exists only locally and is excluded from Git is not a Git-leak finding. The values of `.env` are not included in results.
6. If the user chooses web scanning, candidate open local ports are shown. If the target is not in the list, the number is taken via `Other port`. After an HTTP check, the `<title>`, URL, response status, and inferred technology are shown, and the user answers `Y/N` to "Is this this project's service?". The user's confirmation is a choice of target, not a mechanical proof linking the code and the port.
7. The code is the primary analysis target; the selected local service's responses/security headers and reachable unauthenticated URLs are secondary targets. Post-login screens are explored in a limited way only when the user logs in directly in a temporary browser session. It does not auto-submit forms, upload, perform known state-changing actions, or guess passwords. However, `GET` requests can also have side effects depending on the server implementation, so PGARD does not guarantee no changes, and shows the user the exploration scope and residual risk.
8. Results are normalized to the common schema, deduplicated, and masked, then shown in the CLI or the local web. If the user requests it, HTML/PDF is saved to a local path. Scan sessions, except for the save path, are released from memory at exit.

#### Defense boundaries of local HTTP and the local web server

- HTTP scan targets are limited to numeric `127.0.0.1` and explicitly allowed IPv6 loopback. Arbitrary hostnames, external IPs, Unix sockets, and schemes such as `file:` are rejected. At every redirect step the loopback/allowed-port conditions are re-checked, and the scan stops if they are violated. That a port is open or that a page has a title does not imply access to the project source.
- Port candidate detection confirms by request/response whether the port actually speaks HTTP. A service is not assumed from a standard port number. If port enumeration is restricted by OS permissions, the list may be incomplete, and `Other port` is provided.
- The Node process of the separate web product must apply these protections: it binds only to `127.0.0.1`; a random token is created per session and required for all local APIs; `Origin`/`Host` checks, CSRF defense and default CORS blocking are in place; there is no API that reads arbitrary paths, and only the user-selected project path is allowed; `Cache-Control: no-store` is applied to result responses; and on local server shutdown, the token and the authenticated browser session are discarded.
- Project code is not handed to the browser wholesale. Only the necessary finding locations and secret-masked evidence are passed. An explicit folder selection/confirmation step in the local launcher is provided so that the local web cannot choose an arbitrary project path through web requests alone.
- The local web product's terms of service and privacy notice state the one-time local processing of scan data, the external communication needed for GitHub authentication/permission lookups and optional advisory updates, and the user's responsibility for managing the HTML/PDF reports they save themselves. Because `GET` exploration can change state in a poorly implemented app, the UI does not guarantee no changes.

### 4. Implementation order of the first scan rules

| Group                        | Concrete MVP detection                                                                                                                              | Default judgement limit                                                                                     |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| SQL Injection                | JS/TS `pg`, `mysql2`, Prisma raw; Go `database/sql`, GORM: SQL string concatenation/interpolation → execution flow. Parameter binding is distinguished | First version starts with function/argument flows that can be verified. Dynamic calls and user-defined wrappers may be `not tested/suspected` |
| XSS                          | Input flowing into dangerous outputs such as `innerHTML`, React `dangerouslySetInnerHTML`, Vue `v-html`                                              | Not confirmed from API usage alone                                                                          |
| SSRF, command execution, file paths | Server HTTP requests to input-derived URLs, shell execution arguments, possible manipulation of upload/download paths                        | Evaluate together with domain allow policy and path-normalization evidence                                  |
| Authentication, access control | Authentication/authorization check patterns on protected routes, session cookie attributes, object ID use and whether authorization is checked    | Many `needs review` results depending on service roles and middleware configuration                         |
| CSRF, brute-force defense    | CSRF defense settings for state-changing requests that use cookie authentication, attempt limits in login/reset code                                | No actual password attempts. Defense in an external proxy cannot be ruled out from code alone               |
| Cryptography, secrets        | Plaintext password storage patterns, weak hashes / hardcoded keys, secrets in currently tracked files and Git history                               | Raw values must not be printed. Suspicious patterns are marked with possible false positives                |
| Web responses, headers       | TLS/cookie/security headers and read-only response checks of the selected local service                                                             | The absence of a single header does not confirm overall vulnerability                                       |
| Known vulnerabilities        | Match the actually resolved versions of npm-family lockfiles and Go modules against the local advisory DB                                           | Distinguish a found vulnerable version from actual exploitability                                           |

- OWASP Top 10 is used for result classification, and detailed rules are linked to ASVS/WSTG and CWE. To avoid confusing "supported language" with "all rules supported in all languages", results show the scan scope per language.
- The **recommended first supported targets** for SQL libraries are the five families above. TypeORM/Sequelize/Drizzle/Knex etc. are only detected, and the fact that raw query analysis is unsupported is recorded. The actual adapter list is confirmed together with approval of the implementation stack.
- The CVE/advisory DB is matched as a local file whose signature, source, version, and update date have been checked. Updates are run explicitly, and source/lockfiles are not uploaded externally during an update. If the DB is missing or stale, `not tested / data outdated` is shown and no safe verdict is given. [OSV offline mode](https://github.com/google/osv-scanner/blob/main/docs/offline-mode.md)

### 5. Common result contract (JSON v1)

```json
{
  "schemaVersion": "1.0",
  "scanId": "local-session-id",
  "startedAt": "2026-10-23T00:00:00Z",
  "target": { "repo": "owner/name", "revision": "git-sha", "webOrigin": "http://127.0.0.1:3000" },
  "coverage": [
    { "area": "source:typescript", "status": "completed", "ruleIds": ["PG-SQL-001"], "note": null },
    { "area": "web:authenticated", "status": "not_tested", "ruleIds": [], "note": "no session" }
  ],
  "findings": [
    {
      "id": "stable-fingerprint",
      "ruleId": "PG-SQL-001",
      "title": "Input value concatenated into SQL string",
      "category": "injection",
      "severity": "high",
      "status": "suspected",
      "confidence": "medium",
      "location": {
        "kind": "file",
        "path": "src/api/users.ts",
        "line": 42,
        "url": null,
        "commit": null
      },
      "evidence": "request value → string concatenation → query call (value masked)",
      "impact": "Query structure may be altered",
      "recommendation": "Separate the value as a parameter",
      "references": { "cwe": ["CWE-89"], "owasp": ["A05:2025"], "cve": [] }
    }
  ],
  "advisoryDb": { "version": "bundle-id", "updatedAt": "2026-10-01T00:00:00Z" }
}
```

- `severity`: `critical|high|medium|low|info`; `status`: `confirmed|suspected|informational`; scan failures and out-of-scope items are recorded not as findings but as `coverage.status = not_tested|partial`.
- `confidence` means the strength of evidence. `severity` means the impact and conditions if exploited. The two are not mixed into a single numeric score. Charts show the per-severity finding counts and the not-tested areas separately.
- `location.path` is a repository-relative path. Secret values, tokens, cookies, absolute file paths, DB URL passwords, and sensitive HTTP response bodies are not put in `evidence`. If secret equality comparison is needed, only a session-scoped identifier is used, and neither the raw value nor a recoverable hash is exported.
- Duplicate findings with the same rule, the same code location, and the same cause are merged into one; if the evidence exists in both code and HTTP, the sources are preserved. Reports are rendered from exactly a masked copy of this schema.

### 6. Integration spikes to verify first

1. **Owner-only approval evidence:** A GitHub App installation alone cannot prove the owner's direct approval. Depending on organization settings, a repository administrator may be able to install it, and one must also consider whether an administrator can add a repository to an app the owner installed. Options such as requiring an organization policy that only organization owners install, or requesting minimal organization read permission to restrict installation rights, must be compared for permission and privacy cost. An evidence design that allows re-verifying the owner's identity and the approval scope for a specific repository must be confirmed through official APIs. If the evidence method is not settled, do not relax owner-only; block the scan on that path. [GitHub installation permissions](https://docs.github.com/en/apps/using-github-apps/installing-a-github-app-from-a-third-party)
2. **Contribution decision:** Verify with a test repository which combination of APIs links a GitHub account to the actually merged diff in co-authored commits and squash merges. The name/email in `git log` is only for candidate discovery and is not proof of ownership.
3. **Local web execution:** Test the folder selection / scan permissions of a separate Node launcher and the localhost API defenses, so that the browser does not gain access to all local files.
4. **Offline advisory distribution:** Check the local bundle size, update signature/integrity, GitHub/OSV terms of use, and how outdated data is indicated.

### 7. Completion conditions

- For a personal owner repository, another person's personal repository, and an organization repository, `owner approval + user's current access + merged contribution` are each checked, and if any one condition is missing, analysis does not start. For an organization path where owner-approval evidence is unclear, `blocked` is shown.
- A user who only opened a PR and a commit with only a forged author email do not pass. A local commit absent from the GitHub remote history is not used as evidence of contribution either.
- The CLI and the local web produce identical result JSON for the same fixture and the same selected scope. Each UI shows charts and `file:line`/URL, evidence, guidance, and the `not tested` scope consistently.
- On JS/TS/React/Vue/Go samples, real positive and negative cases of the supported rules are distinguished. Parameter binding and simple use of a dangerous API are not blanket-treated as vulnerabilities.
- A local `.env` not tracked by Git is not judged a Git leak. Secrets in past Git history are found, but raw values do not remain on screen or in JSON, HTML, or PDF.
- HTTP scanning connects only to the selected loopback port and stops on redirects toward external addresses. A port that has not passed the title-confirmation `Y/N` is not linked as a project web scan target.
- Unauthenticated scanning works. Post-login scanning starts only through the user's own login and is discarded after the session ends. It does not perform automatic POST/PUT/DELETE or form submission, but the UI indicates that even GET exploration does not guarantee no changes.
- The web UI server binds only to loopback, and rejects API calls from other web origins and requests without a session token. Reports are written only to the path the user chose.
- The scan code has no path for running the project, installing dependencies, connecting to a DB, Docker scanning, or performance measurement. External network requests that PGARD itself initiates are limited to GitHub authentication/metadata and user-initiated advisory updates.

### 8. Post-MVP candidates

- TypeORM/Sequelize/Drizzle/Knex and more Go framework/ORM adapters.
- Post-login exploration and state-changing request scanning, with a safe scope designed separately.
- Stronger evidence for automatically associating a project with a port (running process, explicit configuration, etc.). Page title + user confirmation remains the MVP's target-selection procedure.
- Direct DB connection, Docker configuration, performance scanning. To be added only after separate policy, permission, and data-handling design.

---

## Agent Execution Guidelines and Ownership

### Original mandatory user instructions

> 1. Split independent work into parallel sub-agent groups, each with a clear result and clear accountability. Have the agents message the responsible agent directly to resolve concrete problems. Have them report when a result changes the plan or cannot be resolved. Integrate and verify the final result.

> 2. Assign two agents concrete deliverables, shared constraints, complementary responsibilities, and the initial drafting work. Both agents do substantive work, and one is designated to compile the deliverables. The two agents cooperate directly and coordinate the division of authority within the approved subsystem without duplicate edits. Changes to deliverables, work scope, or another agent's ownership are reported to the parent agent.

> 3. For each PR awaiting review, create a separate chat to review the changes and report the problems found to you. Manage problem resolution in each chat, and coordinate the whole effort so that each PRo main branch is merged safely. If anything blocks progress, report it to me.

The `PRo main` in the third item is interpreted in context as meaning that **each PR is merged into the main branch**. Because this document workspace currently has no Git repository and no PRs awaiting review, no per-PR chats are created and nothing is merged for now. **When PRs awaiting review actually exist in the future**, create a separate chat for each PR and have each chat handle the independent review and fix confirmation of that PR. The lead owner compiles the findings, checks the required verification and the repository's review and protection rules, and coordinates so that each PR is merged safely into main. Reasons that block progress, such as an unfixable problem, insufficient permissions, conflicts, or CI failures, are reported to the user.

### Actual division of work for writing this document

| Owner                                    | Initial responsibility and deliverables                                                                                                              | Edit ownership                                                                                                                              | Reporting                                                                                          |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| Owner A: product specification and compilation | Organize the confirmed/recommended/undecided content from the conversation, write `work/product_spec.md`, integrate the two drafts, and verify the final document | `work/product_spec.md`, `outputs/PGARD_AGENT_BRIEF_KO.md`                                                                                   | Report final content and scope changes to the lead agent                                           |
| Owner B: technical architecture          | Write the implementation language recommendation, package boundaries, data contract, threat boundaries, prerequisite verification, and completion conditions | `work/technical_architecture.md`                                                                                                            | Deliver results directly to A; report scope and ownership changes to the lead agent                |
| Lead agent                               | Review the independent results, mediate agreements and conflicts, deliver the final result to the user, and incorporate follow-up requests           | During the initial writing did not duplicate-edit the two owners' files; after delivering the integrated version, wrote the follow-up detailed documents | Report blockers and final status to the user                                                       |

The two owners share the same product constraints: only user-approved projects are scanned, code/results are processed locally, the CLI and web have separate UIs, scan semantics are common, and DB, Docker, and performance scanning are excluded from the MVP. A and B coordinated the owner-approval evidence and status-notation issues through direct messages. A wrote the initial integrated version, and afterwards the lead organized the CLI, directory, and development rules into detailed documents in line with user feedback.

### Recommended division of future implementation work

This division is to be finalized at implementation kickoff according to the actual repository structure and the number of owners. Changes to module boundaries are reported to the lead first.

| Work package                              | Owner authority          | Concrete deliverables                                                                                                                                                               | Verification criteria                                                                                                                                                             |
| ----------------------------------------- | ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Permissions, common contract, code analysis | Implementation owner 1 | `policy`/`github-auth`/`git-history`, `scan-core`, common result JSON, JS/TS, React, Vue, Go rules, and Git secret analysis                                                          | Owner-approval, current-access, and contribution gates; positive/negative cases for supported rules; secret masking                                                               |
| Local HTTP, two UIs, reports              | Implementation owner 2   | `http-local`, CLI entry points for `project verify`, per-scope `scan`, `dashboard`, `rules list`, and `doctor`, the standalone CLI TUI and local web UI, HTML/PDF export, common JSON rendering | Same verdicts as the permission module, per-scope coverage, blocking connections outside loopback, Y/N linking, anonymous scanning and optional login, no state-changing requests, matching UI results |

The shared contract (`ScanRequest`, `ScanResult`, `Finding`, `Coverage`) is first proposed as a draft by owner 1, and owner 2 directly proposes changes from the consumer's perspective. Before the contract is agreed, the two owners do not implement separate result formats of their own. Implementation owner 2 does not edit scan rule / permission files, and owner 1 does not edit UI/report files. Changes outside the boundary are discussed directly with the relevant owner and the lead is informed. Each owner tests their own results and submits them in reviewable PR units.

### Verification that may block implementation

- **Owner-approval evidence:** A GitHub App installation alone may not prove the owner's direct approval. First verify the evidence procedure against the official API and actual organization/personal repository settings. If there is no evidence, block at the scan gate; do not relax this policy arbitrarily.
- **Contribution linking:** If there is insufficient data linking an account to the actually merged change in squash merges and co-authored commits, do not pass it and mark it as undeterminable.
- **Local product protection:** Test the access control of the local web server itself, the loopback restriction on redirects, and the disposal of authenticated sessions.
- **CVE data:** Decide the source, integrity, and updates of the offline vulnerability DB and how outdated data is indicated.

If a verification result changes the product promise, schedule, or scope, or remains unresolved, the owner immediately notifies the other owner and the lead. The lead reports the impact and options to the user.
