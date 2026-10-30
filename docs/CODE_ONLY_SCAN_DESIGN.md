# Security design: code-only scans without GitHub approval, and the one-screen web flow

> [한국어](CODE_ONLY_SCAN_DESIGN.ko.md) translation available. This English file is the reference; the translation follows it.

> **Status: approved by the owner on 2026-10-29 ([#414](https://github.com/JadenMeister/pgard/issues/414), [#419](https://github.com/JadenMeister/pgard/issues/419)).** Shipped in phases (section 9).
>
> - **Phase 1, the result labelling, is in:** JSON 1.7 `scanBasis`, SARIF, the report banner, the code-only secret wording. Phases 2 (CLI) and 3 (precommit) are in. **Phase 4 is in:** `pgard web` opens the simple screen (choose a folder, Scan runs the gate first, a code-only scan only on its own click); the `PGARD_WEB_PROTOTYPE` flag is gone. The README remains the source of truth for current behaviour.
> - **Decisions** are marked **[Owner decision Dn]**; all of them were decided on 2026-10-29 as recommended (section 11).

Back to the [README](../README.md) and the [documents index](README.md).

## 1. Why this changes

Today PGARD runs no analysis until all five authorization checks pass (README, [Authorization model](../README.md#authorization-model)). The owner's feedback on 2026-10-29 was:

- the web version has too many tabs and panels;
- it is unclear how to use it;
- it depends too much on the GitHub App.

What the owner wanted: choose a folder and, if the GitHub App is not installed, still find vulnerabilities, without Git history.

The owner chose this policy:

| Area                                                                              | Without approval                          | With approval (all five checks pass) |
| --------------------------------------------------------------------------------- | ----------------------------------------- | ------------------------------------ |
| Current files on disk: source rules, secrets in files, dependencies (offline OSV) | **Runs**, labelled "not authorized"       | Runs (today's behaviour)             |
| Git history (commits, tracked files read from Git objects)                        | Gated                                     | Runs                                 |
| Local web-service checks (`scan web`)                                             | Gated                                     | Runs                                 |
| Result storage (trend, baseline, `report`, incremental state)                     | Gated: a code-only result is never stored | Runs                                 |

## 2. What a code-only scan is

### 2.1 What it reads

- The **files in the chosen folder on this computer**, read like any local linter reads them, with the user's own file permissions.
- It reads only what the user can already open in an editor.
- It runs the same source rules as the `code` scope today (JavaScript, TypeScript, Vue, Go, Java, Kotlin, Python, PHP).
- It runs the dependency check against the **OSV data already on disk** (`pgard advisories update`). A scan never downloads it.
- It runs a **new secrets pass over the files on disk** (`secrets:working-tree`, section 2.3).

### 2.2 What it never does

- It **reads no Git object**: no commit, no tracked-file blob, no index. It does not need `.git` and never runs `git` on the folder's history.
- It makes **no network connection**:
  - no GitHub API call, no sign-in, no device flow, no keychain read for the scan itself;
  - nothing to the target, and no local port probing;
  - the only external data is the OSV data that is already on disk.
- It **stores nothing**: no result in the store, no incremental state, no recent entry beyond what the picker already keeps, and no trend.
- It **executes nothing** from the project (unchanged rule: analyzers are read-only).
- It **never upgrades itself** into an authorized result, and it never reuses an earlier authorization.

### 2.3 Secrets in current files: a new area

Today the secret rules (`PG-SECRET-001` `.env` file, `PG-SECRET-002` credential) run **only in the history scope**. That scope reads tracked files and commits from Git objects. So a code-only scan needs its own pass.

- Phase 1 adds `scanWorkingTreeSecrets` (`packages/scan-core/src/working-tree-secrets.ts`), area `secrets:working-tree`.
  - Same detection and decoding as `pgard precommit`: `scanStagedSecrets` with every line counted as new; UTF-8 and UTF-16 (with or without a byte order mark, plus the UTF-8 reading of UTF-16 bytes); NUL bytes in text read as spaces.
  - A `.env` file is reported by its name even when it is too large, binary or unreadable (as `scanStagedPaths` does for staged files).
  - Every file is read with `O_NOFOLLOW | O_NONBLOCK` and checked again on the open handle (`readSmallRegularFileBytes` in `packages/git-history/src/safe-read.ts`): a symbolic link, FIFO or device swapped in is never followed or read, and cannot block.
  - It skips `.git`, `node_modules`, `bower_components`, `.hg` and `.svn`.
  - Bounds (a hostile tree cannot make it do unbounded work): directories are read entry by entry (`opendir`); at most 300,000 directory entries, 20,000 files, 1 MiB per file, 64 MiB in total, 24 folders deep and 20 s; cancellation is checked on every entry.
  - Anything left out (a limit, a file over 1 MiB, an unreadable file or folder, a file that only looks binary by its content) makes the area `partial`, and the note names up to five files per kind. Only a file in a known binary format (PNG, ZIP, ...) is skipped by design, as in the pre-commit check, and named in the note. The pre-commit check uses the same detection, but there a binary-looking file (`binary_suspected`) is a named warning and never blocks a commit, because many real binary formats have no signature PGARD knows; in the code-only scan the area is still `partial`, which says what happened without blocking anything.
  - Limits in the note never round down to 0 (`<1 MiB`, `<1 s`).
  - It never puts a value in a finding.
- **Wording.** These findings use the working-tree title variants (`FINDING_TEXT_VARIANTS` in `packages/findings/src/rule-text.ts`): "Secret in a project file" and "Environment file in the project folder", never "tracked file" or "committed to Git".

## 3. Threat model

### 3.1 Assets and actors

- **Assets.**
  - Other people's private code and secrets.
  - Live services, including someone else's web app on a reachable port.
  - The credibility of a PGARD result ("PGARD says this repository is clean, and I was allowed to scan it").
- **Actors.**
  - The honest owner or contributor (the common case).
  - Someone who holds a copy of code they have no rights to.
  - Someone who wants a PGARD result to look like an authorized audit.

### 3.2 Why a rule keyed on `.git`, the remote or sign-in protects nothing here

The owner first considered: "if a `.git` folder exists, require the user's GitHub sign-in first". The owner then saw the flaw. **This design rejects that variant (section 3.5).** In general:

- **Any condition on `.git`, the remote or a GitHub sign-in is bypassed in seconds:**
  - download the code as a zip, so there is no `.git`;
  - delete `.git`, or remove or rewrite the remote;
  - copy the files to another folder.
  - The code is the same; only the metadata PGARD could check is gone.
- **So such a rule only punishes the honest user.** For example, someone whose App install is pending would have to delete `.git` to get a scan, while the person who should be stopped is not stopped.

### 3.3 Why a code-only scan of local files is acceptable

- **It gives an attacker nothing beyond freely available tools.**
  - Static analysis of files you already hold is what `grep`, ESLint, semgrep, gitleaks, trufflehog (filesystem mode), trivy (filesystem mode) and the CodeQL CLI do.
  - None of them asks for permission, and PGARD's rules are documented in the README and in `rules list`.
  - The PGARD code-only scan is equivalent to a local linter.
- **It reaches no one else's system or account data.**
  - It reads bytes the user can already read and sends nothing anywhere.
  - If someone holds stolen code, the harm (holding and reading it) has already happened. Running a linter over it adds no new access.
- **The secrets pass reads only what is on disk.**
  - It finds the same strings `grep -r AKIA` finds.
  - It never shows a secret value: findings carry a redacted description and a location.

### 3.4 What stays gated, and why

The gate exists for actions that **reach beyond the files in front of the user**, or that **make a claim about a repository**:

- **Git history.**
  - History holds what is no longer visible: deleted secrets, old commits, other people's work.
  - Scanning it is "mining a repository", which the owner's approval should cover.
  - Today it also needs a repository verified on GitHub, so that what is analysed is tied to an authorized repository.
  - Unchanged.
- **Local web-service checks.**
  - These send HTTP requests to a running service.
  - That is acting on a live system, which may not be the user's.
  - Unchanged: the gate, plus the user-confirmed `127.0.0.1` target.
- **Result storage**, and everything built on it (trend, baseline, `pgard report`, incremental reuse).
  - A stored result is keyed by GitHub's numeric repository id, which only the gate proves.
  - Storing unauthorized results would let them be mistaken later for audited ones, and would mix results of different code under one key.
  - A code-only result is never stored (the server and CLI refuse; the result-store also refuses a result marked `code_only`, as defence in depth).

### 3.5 Rejected alternatives

| Alternative                                                | Why rejected                                                                                                                                                                                                                                                                                                                       |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| "If `.git` exists, require GitHub sign-in first"           | Bypassed by a zip download or `rm -rf .git` (section 3.2). It adds a network dependency and a sign-in for exactly the honest users, and stops no one.                                                                                                                                                                              |
| "Code-only only for folders without a GitHub remote"       | Same bypass. It also punishes the main case the owner described: a GitHub repository whose App is not installed yet.                                                                                                                                                                                                               |
| "Require sign-in, but not owner approval, for code-only"   | A sign-in proves an identity, not a right to this code. It adds the device flow and network access without changing what an attacker can do.                                                                                                                                                                                       |
| "Keep everything gated" (today)                            | The owner rejected it: it blocks the simplest, safest use.                                                                                                                                                                                                                                                                         |
| "Run the gate first; if it blocks, fall back to code-only" | It makes a code-only scan slow and online (GitHub calls, up to a 15 s time limit) and starts sign-ins. The gate runs only where the user asks for an authorized scan (`scan history`, `scan web`, `scan all`, `--require-authorization`, the full dashboard), and a block there is reported, never turned into a code-only result. |

**Recommendation: a code-only scan works for any local folder, with or without `.git`, a remote or a sign-in.** We found no strong counter-argument.

### 3.6 Residual risks and proportionate mitigations

| Residual risk                                                                         | Mitigation (none of them burdens an honest user)                                                                                                                                                                                                                                                                                                                                                                                             |
| ------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A code-only result is presented as an authorized audit ("PGARD-verified").            | **Clear labelling everywhere**: the UI badge, the terminal line, a JSON/SARIF field (section 4), and a banner on every report page. **No "verified" wording or badge** ever appears for a code-only result. `authorization.decision` is never `allowed`.                                                                                                                                                                                     |
| Unauthorized results pile up next to authorized ones.                                 | **No storage** of code-only results (section 3.4); the store refuses them.                                                                                                                                                                                                                                                                                                                                                                   |
| A wrapper or CI step treats exit code 0 of a code-only run as "authorized and clean". | `scanBasis.authorization: "not_verified"` in JSON and SARIF, plus `--require-authorization`, which restores exit 3 (section 5).                                                                                                                                                                                                                                                                                                              |
| Someone scans code they have no rights to.                                            | Accepted. It is equivalent to running any free linter on files the user already holds (section 3.3), and PGARD adds no access. The legal notice on first use already says to scan only what you are allowed to.                                                                                                                                                                                                                              |
| A secret found on disk is shown on screen.                                            | Unchanged rule: values are never shown, only the kind and the location.                                                                                                                                                                                                                                                                                                                                                                      |
| A hostile folder (huge tree, symbolic-link loops, giant files) slows the scan.        | The same limits as the code scope, plus the secrets-pass limits (section 2.3). The pass never follows links. A limit marks the area `partial`, never "clean".                                                                                                                                                                                                                                                                                |
| The web server becomes a way to read arbitrary folders.                               | The folder is chosen by the user in the OS folder dialog (or pasted) on a token-gated page; the server resolves it with realpath and checks the whole folder chain for ownership and write bits in the inspector child; home, its parents and top-level folders are refused; the checks run again before every scan; findings are redacted and paths are repository-relative. Token, Host and Origin checks; `127.0.0.1` only (section 6.1). |

## 4. How results are labelled

### 4.1 JSON result: `schemaVersion` 1.7 (a minor bump)

A new optional top-level field, `scanBasis`:

```json
"scanBasis": {
  "mode": "code_only",
  "authorization": "not_verified",
  "reason": "no_github_remote"
}
```

- **`mode`.**
  - `"authorized"`: the gate ran (`authorization` says whether it passed: `verified`, or `not_verified` with `reason: "no_approval"`, or `"check_failed"` when the gate could not finish because of an internal error).
  - `"code_only"`: no gate ran.
  - The field is absent in results of 1.6 and older, and a reader treats absent as `"authorized"`, because older PGARD only wrote results after the gate passed.
- **`authorization`.** `"verified"` or `"not_verified"`. This is the coordinator's `authorization: "not_verified"`. It sits in a new object, because retyping the existing `authorization` object would be a major change.
- **`reason`.** `null` exactly when `authorization` is `verified`; otherwise an open-ended code:
  - `no_approval` (the gate ran and did not pass),
  - `check_failed` (the gate could not finish: an internal error; `overallStatus` is `failed`),
  - `not_checked` (the user asked for code-only),
  - `no_github_remote`,
  - `not_a_git_repository`,
  - `offline`.
- **No closed enum gains a value.**
  - `authorization.decision` stays `blocked`, which is truthful: the gate did not allow this scan.
  - Every check is `unverifiable` with the fixed reason "Not checked: this was a code-only scan of the files on this computer. No authorization was proven."
  - `requestedScopes` is `["code"]`.
- **`overallStatus`.**
  - It is derived from the code coverage alone (`completed`, `partial` or `failed`), never `blocked`, because analysis did run.
  - An old reader sees `decision: "blocked"` and fails safe: nothing that checks `decision === "allowed"` treats it as authorized.
  - An old reader that uses `overallStatus` to mean "did analysis run" stays correct.
- **Code-only is known from `scanBasis` only.** `decision: "blocked"` with a status other than `blocked` does **not** mean code-only: a gate that fails internally also gives `blocked` / `failed` (with `reason: "check_failed"`).
- **Cross-field checks (the reader refuses anything else).**
  - `authorization: "verified"` needs `decision: "allowed"` with all five checks `passed`.
  - `mode: "code_only"` needs `decision: "blocked"`, `requestedScopes: ["code"]` and `authorization: "not_verified"`.
  - `mode: "authorized"` with `authorization: "not_verified"` needs `overallStatus` `blocked` or `failed` and no findings (the gate stopped the scan before any analysis).
  - `reason` is `null` exactly when `authorization` is `verified`.
  - From 1.7 on `scanBasis` is required, so deleting it from a file cannot drop the label.
- **Old readers.** A reader of 1.6 or older does not know the field and drops it: it shows a code-only result as an ordinary blocked-gate result without the code-only label (it still never treats it as authorized, because `decision` is `blocked`). Only 1.7 readers show the label.

### 4.2 SARIF

- `runs[0].properties.pgard.scanBasis` carries the same object.
- `runs[0].invocations[0].toolExecutionNotifications[]` carries one `warning`: "Code-only scan: authorization was not verified. Only the current files were checked; Git history and web checks did not run." (`CODE_ONLY_SARIF_NOTICE`).
- Uploaders that show notifications (GitHub code scanning does) show it next to the results.
- `runs[0].automationDetails.id` is `pgard/code-only/`, so GitHub code scanning keeps code-only results in their own category, apart from authorized runs.
  - **An upload `category` does not override it.** `github/codeql-action/upload-sarif` fills `automationDetails` from its `category` input only for runs that have none (`populateRunAutomationDetails` in `src/upload-lib.ts`, checked 2026-10-29); PGARD always writes the id, so a code-only run stays in `pgard/code-only/` whatever `category` the workflow passes.
  - An old reader of the SARIF that ignores `properties` and notifications still sees the separate category.

### 4.3 Text, reports and the dashboard

- **Terminal.** The first line of the result is `! Code-only scan: authorization not verified (current files only; no Git history, no web checks, not saved).`, followed by one line on how to get an authorized scan.
- **HTML and PDF report.** Every page carries a banner, and the cover says "Not authorized: code-only scan". There is no "verified" wording. Implemented in phase 1 (`packages/report/src/code-only-text.ts`): an HTML banner that is repeated on every printed page (a table header row that browsers repeat on each page, above the content, so it never covers it) and a PDF banner drawn on every page once all pages exist (`bufferPages`), so it never changes the font of the text that flows onto a new page, plus a cover block with the reason (`scanBasis.reason`).
- **Web.**
  - The results card always starts with the label **"Not authorized · code only" / "권한 미확인 · 코드만"** and a short explanation.
  - The label cannot be dismissed while the result is on screen.
  - Screenshot: `*-6-not-authorized-label.png`.

## 5. CLI behaviour

**[Owner decision D1] What `pgard scan` does without approval.**

**Revised 2026-10-30 (phase 2b):** authorization first, then a y/N question; without a terminal it blocks; `--code-only` opts in. `pgard scan` and `pgard scan code` run the gate as before. When it fails (no approval, `check_failed`, no GitHub remote, not a Git repository) and stdin and stdout are a terminal, PGARD asks "Skip Git history and scan only the current code? (marked as not authorized) [y/N]". N (the default) exits 3 with the approval guidance; y runs the code-only scan with the gate's reason. Without a terminal (CI, pipes, a machine format sent to a pipe) nothing is asked: exit 3 and "For a code-only scan, add --code-only." `--code-only` skips the gate (no network). `--require-authorization` is removed. The too-broad, home and `.git` refusals apply either way. A folder they refuse is refused at once, never offered. A gate that does not pass exits 3 in every scope, also when it could not finish (`check_failed`; each GitHub request has a 10 s limit); 5 is for unexpected internal errors only.

~~Decided 2026-10-29: code-only by default for the `code` scope, with a clear note. Strict mode is opt-in.~~ Superseded by the revision above; the table below shows the 2026-10-29 proposal.

| Command                                   | Today                               | Proposed                                                                                                                                                                                                                                                                                                          |
| ----------------------------------------- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pgard scan code`                         | Gate; blocked → exit 3, no analysis | **Runs code-only** in any folder (no Git and no GitHub needed), never signs in, and prints the code-only line. Exit 0 / 4 from code coverage. An authorized code scan is asked for with `--require-authorization` (next row).                                                                                     |
| `pgard scan code --require-authorization` | n/a                                 | Today's behaviour: the gate runs first; allowed → an authorized scan (stored as today); blocked → exit 3, no analysis. For people and wrappers that want proof.                                                                                                                                                   |
| `pgard scan history`, `scan web`          | Gate                                | **Unchanged** (exit 3 when blocked). The blocked message adds: "`pgard scan code` checks the current files without approval."                                                                                                                                                                                     |
| `pgard scan all`                          | Gate                                | **[Owner decision D2]** Decided 2026-10-29: **unchanged** (gate; blocked → exit 3, plus the same hint). Alternative: run code-only for `code`, mark `history` and `web` `not_tested` ("needs owner approval"), exit 4. The first keeps "all" honest; the second is friendlier but hides a block behind a partial. |
| Interactive menu (`pgard`)                | Guided sign-in and App install      | The first choice becomes "Scan the current files (code only)". Sign-in and App install are offered afterwards as "Also scan Git history".                                                                                                                                                                         |
| `pgard project verify`                    | Gate only                           | Unchanged. One added line when blocked: "Without approval, `pgard scan code` runs a code-only scan of the current files."                                                                                                                                                                                         |
| `pgard doctor`                            | —                                   | One `[info]` row: "Scans without owner approval run code-only (current files, not saved)."                                                                                                                                                                                                                        |
| `pgard report`, `baseline`, `sbom`, trend | Gated                               | **Unchanged** (they read stored results or claim a repository). `sbom` reads lockfiles only, like the code-only dependency check, so it could follow the same rule later; that is out of scope here.                                                                                                              |

- **Exit codes.** No new code.
  - A code-only scan exits 0 (completed, findings may exist) or 4 (partial), like any scan.
  - Exit 3 stays "blocked by the gate" and appears only when the user asked for authorization (`--require-authorization`, `history`, `web`, `all`).
- **`--format json|sarif`.** Prints the code-only result with `scanBasis` (section 4). Stdout still holds exactly one document.
- **Flags.** One new flag, `--require-authorization` (`code` only; the other scopes always require it). `--code-only` is not needed, because code-only is the default for `code`.

### 5.1 `pgard precommit` (M10-1, #408)

- `pgard precommit` checks **staged changes only**, never history.
- It already reads only the index, which holds the user's own content about to be committed.
- Today it runs the full gate, so without a saved sign-in "the gate blocks and nothing is scanned" (README).

**[Owner decision D3] Decided 2026-10-29: run `pgard precommit` code-only, always, with no gate and no network.**

- **Why.**
  - The staged content is the committer's own change. Authorization adds no protection for it, because the same bytes are on disk and any hook can grep them.
  - The gate costs up to 15 s per commit (`PGARD_PRECOMMIT_TIMEOUT_MS`) and fails offline. A security hook that blocks commits for lack of a GitHub sign-in is the kind of App dependence the owner objected to.
  - Reading the index is the precommit check's own input, not "Git history" in the gated sense: no commit other than HEAD's blob for comparison is read.
- **Labelling.** The summary line says `code-only: authorization not verified`. Exit codes are unchanged except that "not authorized" can no longer happen, so exit 3 disappears from precommit.
- **Alternatives.**
  - (b) Gate only when a saved sign-in exists, and fall back to code-only otherwise: slower, same protection.
  - (c) Unchanged, strict.
  - A repository can opt into strictness with `"precommit": { "requireAuthorization": true }`. The config only ever makes the check stricter, so reading it from the untrusted repository is safe.

## 6. The no-GitHub-remote and no-Git cases

**[Owner decision D4] Decided 2026-10-29: both get a code-only scan.** This matches the owner's intent and section 3.2: the gate's evidence is absent, but code-only needs none of it.

| Folder                                                                  | Code-only scan                       | Gated parts                                                                        |
| ----------------------------------------------------------------------- | ------------------------------------ | ---------------------------------------------------------------------------------- |
| GitHub remote, App not installed or approval missing                    | Yes                                  | Offered: "Connect GitHub to also scan Git history"                                 |
| GitHub remote, approved                                                 | Yes (or authorized, if chosen)       | Available                                                                          |
| Git repository, no remote, or a non-GitHub remote (GitLab, self-hosted) | Yes (`reason: no_github_remote`)     | Not available. The message says why: owner approval is proven through GitHub only. |
| Not a Git repository (zip download, new folder)                         | Yes (`reason: not_a_git_repository`) | Not available.                                                                     |

Web picker changes (implemented in the prototype):

- **Candidates.**
  - Today the picker lists only Git repository roots with one GitHub remote, and blocks `no_remote`, `remote_not_github`, `remote_ambiguous` and `not_a_git_root`.
  - Under this design those blocks apply to **authorized** scans only. On the simple screen the folder is selectable for code-only, with a one-line note ("Not a Git repository: the files are scanned as they are").
  - Blocks about the folder chain itself (`not_owned_by_you`, `group_or_world_writable`, `unsafe_display`) still refuse it.
- **Identity.**
  - A code-only folder's identity is the device/inode chain from its anchor (section 6.1). It has no Git identity (`identity.kind: "folder"`).
  - The same ownership and write-bit checks run again before every scan (a new `folder` inspection: the chain only, no Git calls).
  - Every route that runs the authorization gate (`/api/auth/verify`, owner approval, `POST /api/scan`, the web target) refuses a folder project with `409 code_only_project`; only `POST /api/code-scan` accepts it. The recent list stores no folder project.

### 6.1 Choosing the folder: the OS folder dialog or a pasted path

The owner found the name search confusing ("type `latent`" → "no folder named `latent` in the search folders … `pgard web scope add`"). The folder is now chosen the way every desktop app does it.

- **Choose folder.** The button sends a token-gated `POST /api/picker/browse`. The **server** opens the operating system's folder dialog and the page polls `GET /api/picker/browse` until it closes (the HTTP request time limit is 30 s, a person may take longer):
  - macOS: `/usr/bin/osascript -e activate -e 'POSIX path of (choose folder with prompt "…")'`.
  - Windows: **not supported.** The folder checks and the pasted-path rules are POSIX-only (`/`-separated, `lstat` ownership and mode bits), so there is no Windows dialog; the page shows the "no folder window" state, and a pasted `C:\` path is refused as `bad_path`. Windows support needs its own path and ownership checks first.
  - Linux: `/usr/bin/zenity --file-selection --directory`, else `kdialog --getexistingdirectory`.
  - None available: "This computer has no folder window PGARD can open. Paste the folder's path below instead."
- **Paste a path.** A text box below the button (`POST /api/picker/path`). `~` and `~/…` expand to the home folder; `~user`, relative paths, NUL and more than 4096 characters are refused (`bad_path`).
- **No scope step.** There is no search-folder list and no `pgard web scope add` on this path. The name search stays only in the full dashboard.
- **Validation (unchanged rules, new entry).** A new inspector job `resolve` runs in the child process, never in the server:
  - `realpath`, then `lstat`: it must be a directory. A symbolic link is resolved to its real folder, never trusted as a name.
  - Refused: `/`, top-level folders (`/usr`), the home folder and its parents (`too_broad`); more than 24 folders below the anchor (`too_deep`); missing, a file, unreadable.
  - **Anchor.** Inside home: the home folder. Outside home: the highest folder above it still owned by this user; the folder above the anchor must not be writable by others unless sticky (like `/tmp`).
  - From the anchor down, every folder is walked by name with `lstat` and the same `not_owned_by_you` / `group_or_world_writable` rules as a search candidate; the display-safety check (`unsafe_display`) is the same.
  - Then the usual `full` inspection decides between a normal GitHub candidate and a code-only one (section 6).
  - Every refusal has a reason and a fix, in English and Korean (for example "This is your home folder or a system folder, not a project. Choose the project's own folder, for example ~/code/my-app.").
  - A folder chain another user owns or could change is a refusal (`not_owned_by_you`, `group_or_world_writable`) with the folder's own wording, which does not mention `.git`.
  - Paths in a refusal go through the same display-safety check as a candidate's path: a name with control, invisible or look-alike characters is shown escaped (`\u{202e}`), never as is.
  - A folder chosen in the dialog or pasted is never written to the recent list.
- **Dialog route security.**
  - The same token, Host and Origin middleware as every API route; the routes are a 404 unless the simple screen is on.
  - One dialog at a time (`409 dialog_open`); a 5-minute time limit; the dialog process is killed on cancel, on server shutdown and on timeout.
  - Fixed argv through `execFile` with `shell: false`; the only text in the arguments is PGARD's own localized prompt, never request data.
  - The result is kept in the server session and returned only through the token-gated status route, as a candidate with a `~`-shortened path, never the raw string.
  - Cancel is a normal state ("No folder was chosen."), not an error.
- **Rejected: the name search with search folders** (today's picker, used by the first prototype). The browser could send only a name, so the server had to search a list of "search folders" and the user had to understand and extend that list (`pgard web scope add`) before a folder outside it could be found. The dialog gives the server the same thing — a path the user picked on their own screen — without that concept; the path checks that made the search safe are applied to the chosen folder unchanged.

## 7. Web UX: one screen

### 7.1 Flow and states

The screen is one column with three numbered cards and a collapsed **More**.

```
pgard  [Prototype]                                         한국어 | English
Scan a project folder
PGARD checks the files in a folder on this computer for leaked secrets, risky code and known-vulnerable dependencies.
(1) Choose a folder   (2) Press Scan   (3) Fix what it finds

┌ 1. Folder ───────────────────────────────────────────────┐
│ [ Choose folder ]                                         │
│ Or paste the folder's path [ ~/code/my-app ________ ] [Check] │
│ Scan this folder?  ~/projects/sample-shop   [Use this folder] │
└──────────────────────────────────────────────────────────┘
┌ 2. Scan ─────────────────────────────────────────────────┐
│ Reads the current files only … nothing is saved.  [ Scan ] │
└──────────────────────────────────────────────────────────┘
┌ 3. Findings ─────────────────────────────── 5 findings ──┐
│ ● Not authorized · code only   Authorization was not checked │
│   … Connect GitHub to also scan Git history (optional)     │
│ severity bar · findings table (rule, file:line, details)  │
└──────────────────────────────────────────────────────────┘
▸ More
```

| State                | What the user sees                                                                                                                                                                  | Screenshot                     |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ |
| Empty                | Title, one-sentence lead, the three steps, the folder card (**Choose folder** and the paste box), a disabled Scan card.                                                             | `*-1-empty.png`                |
| Refused path         | The reason and the fix under the paste box (here: the home folder).                                                                                                                 | `*-2-refused-home.png`         |
| Folder without Git   | "Scan this folder?" with the real path and "Not a Git repository: the files are scanned as they are." (D4)                                                                          | `*-3-confirm-no-git.png`       |
| GitHub repository    | "Scan this folder?" with the real path and the GitHub repository; **Use this folder** and **Back**.                                                                                 | `*-4-confirm-repo.png`         |
| Folder chosen        | "Folder **sample-shop** owner/repo" with **Change**; Scan is enabled.                                                                                                               | `*-5-folder-chosen.png`        |
| Scanning             | A spinner, "Scanning the files… N s" and **Cancel**. Change is disabled.                                                                                                            | `*-6-scanning.png`             |
| Results              | Count, the **not authorized** label, a partial notice when an area could not run (for example no OSV data), the severity bar (click to filter) and the findings table with details. | `*-7-results.png`              |
| Not-authorized label | Badge, one sentence, and the optional link to connect GitHub.                                                                                                                       | `*-8-not-authorized-label.png` |
| More open            | "What was checked", standards, rule statistics, plus Trend and Export (disabled with the reason) and Full dashboard.                                                                | `*-9-more.png`                 |
| Dialog open          | "Waiting for the folder window…" and **Cancel**; closing the window without a choice shows "No folder was chosen."                                                                  | —                              |
| No findings          | "No findings in the checked files." The label is still shown. Never "safe".                                                                                                         | —                              |
| Cancelled / failed   | One notice; Scan again.                                                                                                                                                             | —                              |

### 7.2 Copy (EN / KO)

| Key              | English                                                                                                                                                              | 한국어                                                                                                                                                                         |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Title            | Scan a project folder                                                                                                                                                | 프로젝트 폴더 검사                                                                                                                                                             |
| Lead             | PGARD checks the files in a folder on this computer for leaked secrets, risky code and known-vulnerable dependencies.                                                | PGARD는 이 컴퓨터에 있는 폴더의 파일에서 유출된 비밀값, 위험한 코드, 알려진 취약 의존성을 찾습니다.                                                                            |
| Steps            | Choose a folder · Press Scan · Fix what it finds                                                                                                                     | 폴더 선택 · 검사 누르기 · 찾은 문제 고치기                                                                                                                                     |
| Folder hint      | Choose the project's folder, or paste its path.                                                                                                                      | 프로젝트 폴더를 선택하거나 경로를 붙여 넣으세요.                                                                                                                               |
| Button           | Choose folder                                                                                                                                                        | 폴더 선택                                                                                                                                                                      |
| Paste box        | Or paste the folder's path · Check                                                                                                                                   | 또는 폴더 경로 붙여 넣기 · 확인                                                                                                                                                |
| No dialog        | This computer has no folder window PGARD can open. Paste the folder's path below instead.                                                                            | 이 컴퓨터에는 PGARD가 열 수 있는 폴더 선택 창이 없습니다. 아래에 폴더 경로를 붙여 넣으세요.                                                                                    |
| No Git (D4)      | Not a Git repository: the files are scanned as they are.                                                                                                             | Git 저장소가 아닙니다. 파일을 있는 그대로 검사합니다.                                                                                                                          |
| Refusal example  | This is your home folder or a system folder, not a project. Choose the project's own folder, for example ~/code/my-app.                                              | 홈 폴더나 시스템 폴더이며 프로젝트 폴더가 아닙니다. 프로젝트 자체의 폴더를 선택하세요. 예: ~/code/my-app                                                                       |
| Scan explanation | Reads the current files only: secrets, risky code patterns and dependencies. No Git history, nothing leaves this computer and nothing is saved.                      | 현재 파일만 읽습니다: 비밀값, 위험한 코드 패턴, 의존성. Git 기록은 읽지 않고, 이 컴퓨터 밖으로 아무것도 보내지 않으며, 아무것도 저장하지 않습니다.                             |
| Badge            | Not authorized · code only                                                                                                                                           | 권한 미확인 · 코드만                                                                                                                                                           |
| Badge text       | This is a code-only scan of the files on this computer. PGARD did not prove that you may scan this code, so Git history, local web checks and saved results are off. | 이 결과는 이 컴퓨터에 있는 파일만 검사한 코드 전용 검사입니다. 이 코드를 검사해도 된다는 권한을 PGARD가 확인하지 않았으므로 Git 기록, 로컬 웹 검사, 결과 저장은 꺼져 있습니다. |
| Upgrade link     | Connect GitHub to also scan Git history. Optional: opens the full dashboard, which asks for GitHub sign-in and owner approval.                                       | GitHub 연결하고 Git 기록도 검사. 선택 사항: GitHub 로그인과 소유자 승인을 요청하는 전체 대시보드를 엽니다.                                                                     |

All strings are in `apps/local-web/src/client/features/simple/simple-text.ts`.

### 7.3 What moves under "More"

| Today (tabs and panels)                                                 | In the one-screen flow                                                                                                   |
| ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Overview (summary panels, charts)                                       | Removed. The count, severity bar and table are the overview.                                                             |
| Findings (filters, groups, paging)                                      | **Main screen** (severity filter and paging). The other filters (rule, file, area, category) move under More in phase 4. |
| Coverage, activity log, advisory status                                 | More › What was checked                                                                                                  |
| Standards (OWASP, CWE)                                                  | More › Standards                                                                                                         |
| Rule statistics                                                         | More › Rule statistics                                                                                                   |
| Trend                                                                   | More › Trend: only for authorized scans (needs storage). Otherwise disabled, with the reason.                            |
| Export                                                                  | More › Export: authorized results as today; code-only results once the report banner exists (D5).                        |
| Authorization panel, scan-scope toggles, web target panel, session menu | Leave the main path. They appear after **Connect GitHub to also scan Git history**, in the authorized flow.              |
| Legal notice                                                            | Kept on first use (the same text), shown above the folder card.                                                          |

**[Owner decision D5] Export of code-only results.** Decided 2026-10-29: allow HTML and PDF export with a "Not authorized: code-only scan" banner on every page, because the file is the user's own local output, like `--format json`. Alternative (rejected): no export without approval. Phase 1 implements the banner, and the prototype exports with it.

### 7.4 The approval upgrade is a link, not a blocker

- The upgrade is offered in two places: in the not-authorized label and under More › Full dashboard.
- The text is **"Connect GitHub to also scan Git history"**. It never says "required".
- It opens the authorized flow: sign-in, App install guide, owner approval, then Git history and web checks.
- When that flow ends with `allowed`, the authorized scan replaces the code-only result, and the label switches to "Authorized" with the five passed checks.
- In the prototype the link opens today's full dashboard in the same tab.

## 8. Migration

- **`pgard web`.**
  - It becomes the one-screen flow, with the picker as step 1.
  - The full dashboard stays reachable as More › Full dashboard (the "authorized flow") until phase 4 folds its remaining parts into the screen.
  - The `#findings`, `#coverage` and similar hashes keep working inside the full dashboard.
- **`pgard dashboard`** (fixed project, from the terminal).
  - It opens the same one-screen flow with step 1 already filled in and no **Change**.
  - The launcher still requires a Git root today. Phase 4 relaxes this to "any folder" for code-only.
- **Stored results.**
  - Unchanged. Results written before 1.7 are read as authorized (they were).
  - Code-only results are never stored, so the store and the trend contain only authorized scans.
- **Docs.**
  - README: the Policies line "There is no option to skip them" becomes "Git history, web checks and storage need all five checks; `pgard scan code` without approval runs a code-only scan, labelled as not authorized".
  - Update `SECURITY.md` in scope: a code-only result shown or exported as authorized is a vulnerability; a code-only scan of local files is not a gate bypass.
  - Update `RESULT_SCHEMA.md` for 1.7.
- **The mock servers** (`dev/mock-server.mjs`) get one realistic code-only scenario (one project, a few findings) for UI tests, replacing the noisy demo data that confused the owner.

## 9. Phasing (small PRs)

Each phase is its own PR, opened only after the previous one passed review, and each references #414 (and #419 for phase 5).

1. **Design record and result labelling (PR #415).**
   - This document, with the decisions of 2026-10-29.
   - JSON 1.7 `scanBasis` in the contract and the reader; `runCodeOnlyScan` writes `mode: "code_only"`, every authorized scan writes `mode: "authorized"` with `verified` or `not_verified` / `no_approval`.
   - SARIF: `properties.pgard.scanBasis`, the code-only warning notification and the `pgard/code-only/` category.
   - HTML and PDF reports: the banner on every page and the cover block (D5); the prototype exports with it.
   - The result store refuses a result whose authorization is not verified (defence in depth).
   - The secrets pass on the files on disk uses its own texts ("Environment file in the project folder", "Secret in a project file"), never "tracked file" or "committed to Git"; same rule ids and fingerprints.
   - The web label says why authorization is not verified (no GitHub remote, not a Git repository, not checked).
   - `RESULT_SCHEMA.md` for 1.7.
   - The prototype route and screen stayed behind `PGARD_WEB_PROTOTYPE=code-only` (removed in phase 4).
2. **CLI (D1, D2, D4).** `pgard scan code` code-only by default, `--require-authorization` (phase 2b, 2026-10-30: authorization first, a y/N question in a terminal, `--code-only`; `--require-authorization` removed), the terminal line, `scan all` and `history`/`web` unchanged with the hint, `project verify` and `doctor` rows, any folder (no Git, no remote), README.
3. **Precommit (D3).** `pgard precommit` code-only with no gate and no network; `"precommit": { "requireAuthorization": true }` opts in.
4. **Web simple screen, production (done 2026-10-30).** Scan runs the authorization gate first with the existing sign-in only (never a device flow by itself); when it does not pass, one plain line says why and the page offers "Scan code only (not authorized)" and "How to approve"; not signed in shows a quiet "Sign in and check approval" link instead of "How to approve". `pgard web` asks nothing in the terminal, and its search picker uses only saved search folders. "Only after a click" is enforced by the page: `POST /api/code-scan` does not require a gate to have run (a folder without Git never has one); the server enforces the token, Host and Origin checks, the identity re-check, the code-only label with its reason, and that nothing is stored. A `.git` folder (or anything in it, or a bare repository) is refused with the same rule as `pgard scan code`; a folder inside a repository is scanned as that repository. Not yet: `pgard dashboard` keeps the full dashboard, the simple screen's texts stay in their own module, Windows still refuses `pgard web`. The original plan: the one-screen flow with the OS folder dialog and paste box (section 6.1) becomes the default `pgard web` and `pgard dashboard` main path; the prototype flag and route are removed; the old tabs leave the main path (the full dashboard stays the authorized flow behind the upgrade link); i18n moves into the catalogs.
5. **Session URL (#419, section 12).** Browser auto-open, the masked token, `--print-url`, the single-use token, for `pgard web`, `pgard dashboard` and the new screen.
6. **Independent security review** of phases 1–5, before release.

## 10. The prototype in PR #415 (historical; replaced by phase 4)

- **Real.**
  - The OS folder dialog (macOS `osascript`, Linux `zenity`/`kdialog`; none on Windows) and the paste box, resolved and checked in the real inspector child process (realpath, ownership, write bits, display safety), then the confirm and the re-check before the scan.
  - Folders with no GitHub remote and non-Git folders get a code-only scan (D4).
  - The code-only scan (source rules, dependencies against the on-disk OSV data, and the new secrets pass) on the real folder.
  - The redaction.
  - The token, Host and Origin checks, and `127.0.0.1` only.
  - The result labelling of phase 1: `scanBasis` in the result (with the reason from the chosen folder), SARIF, and the HTML/PDF export with the banner on every page (More › Export report).
- **Not real yet.**
  - The upgrade link opens today's full dashboard.
  - The CLI (phase 2) and precommit (phase 3) do not run code-only scans yet.
- **In the published package.** The prototype routes and the simple screen shipped in the `pgard` tarball, off (404) unless `PGARD_WEB_PROTOTYPE=code-only` was set. Phase 4 removed the flag: the routes are on in picker mode, and `POST /api/code-scan` uses the last gate's reason.
- **Never.**
  - The prototype route makes no GitHub call. It is a 404 unless the simple screen is on, and the simple screen is never on in fixed mode.
  - `POST /api/scan` (the gate) is unchanged.
- **Tests.**
  - `packages/scan-core/src/run-code-only.test.ts`: no gate, no history, labelled result.
  - `packages/scan-core/src/working-tree-secrets.test.ts`: secrets on disk, `.env`, links not followed, no Git, no value in output; UTF-16 and NUL-padded text, a large file named and `partial`, a large or binary `.env` reported by name, the entry cap (one huge folder and many folders), the byte cap, the time budget and cancellation.
  - `apps/local-web/src/server/code-scan.test.ts` (was `code-scan-prototype.test.ts`) and `simple-scan.test.ts` (phase 4: gate first, no scan without the click, nothing stored): never on in fixed mode, token, Host and Origin checks, `no_project`, identity re-check, export with the banner.
  - `apps/local-web/src/server/choose-folder-prototype.test.ts`: dialog and paste routes (404 when off, token and Origin, one dialog at a time, cancel and shutdown kill the dialog, unavailable, refusals with fixes, `~` expansion), a non-Git folder is code-only only (`409 code_only_project` on verify and `POST /api/scan`), the folder re-check before the scan, a writable folder chain refused without `.git` wording, refused paths escaped, no recent entry for a chosen folder, and the fixed dialog argv per platform (none on Windows).
  - `apps/local-web/src/server/picker/resolve-folder.test.ts`: the `resolve` job on real folders (GitHub repository, no Git, symbolic link, group-writable, outside home, refused paths) and its message validation.
  - `packages/findings/src/scan-basis.test.ts`: reading `scanBasis` (absent means authorized, impossible combinations refused, `verified` and `code_only` checked against the decision, the checks and the scopes, unknown reason codes kept), SARIF labelling and category, the working-tree secret texts and their Korean translation.
  - `packages/report/src/code-only-report.test.ts`: the HTML banner and cover block, the repeated print header, the PDF banner on every page, and the body font unchanged after a page break.
  - `packages/result-store/src/store.test.ts`: a code-only result is never allowed into the store.

## 11. Decisions (decided 2026-10-29)

The owner approved the design on 2026-10-29; every decision went as recommended.

| #   | Question                                   | Decision (2026-10-29)                                                                                                     |
| --- | ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| D1  | `pgard scan code` without approval         | Revised 2026-10-30: authorization first, then a y/N question; non-TTY blocks (exit 3 + hint); `--code-only` opts in.      |
| D2  | `pgard scan all` without approval          | Unchanged and strict (blocked, exit 3), with a hint to run `scan code`.                                                   |
| D3  | `pgard precommit`                          | Always code-only, with no gate and no network; a repository opts in with `"precommit": { "requireAuthorization": true }`. |
| D4  | No GitHub remote / not a Git repository    | Both get a code-only scan.                                                                                                |
| D5  | Export of code-only results                | Allowed, with a "not authorized" banner on every page.                                                                    |
| D6  | The one-screen layout and copy (section 7) | Approved, together with the OS folder dialog and paste flow (section 6.1).                                                |

## 12. Session URL handling (#419)

Applies to `pgard web`, `pgard dashboard` and the one-screen flow alike (phase 5).

### 12.1 Today

- The launcher prints `http://127.0.0.1:<port>/#token=<secret>` and the user copies or clicks it.
- The token is a long random value in the URL fragment (never sent in requests or `Referer`); the page reads it and sends it as `x-pgard-token` on every API call for the life of the server.
- So the full secret sits in the terminal scrollback, in shell recordings and screen shares, and in the browser history, and the same link works again in any tab until the server stops.

### 12.2 Decisions

- **Open the browser.** After the server listens, the launcher opens the URL with the platform opener: `open` (macOS), `xdg-open` (Linux), `rundll32 url.dll,FileProtocolHandler` (Windows), through `execFile` with a fixed argv and no shell. Not in CI, not without a terminal, and not with `--no-open`.
  - **Linux:** only when `DISPLAY` or `WAYLAND_DISPLAY` is set, and never when `SSH_CONNECTION` is set (the browser would open on another machine's screen, or not at all).
  - **Windows:** before `rundll32` the URL must match `^http://127\.0\.0\.1:\d+/#token=[A-Za-z0-9_-]+$` exactly; anything else is not opened (it is PGARD's own URL, so a mismatch is a bug, never user input).
  - Whenever the browser is not opened, and in the "opened" line too, the terminal mentions `--print-url` ("Not opened automatically. Run again with --print-url to see the full link.").
- **Mask the token in the terminal.** The terminal shows `http://127.0.0.1:4317/#token=•••• (opened in your browser)`. The full URL is printed only when opening failed or was skipped (no opener, CI, no terminal, `--no-open`), or with `--print-url`. The full URL never goes to a log file.
- **Single-use URL token.** The URL token is only an invitation:
  1. On its first load the page calls `POST /api/session/exchange` with the URL token (same Host and Origin checks). The server marks the token used and returns a new **session secret** (32 random bytes, kept only as a hash on the server).
  2. The page removes the fragment from the address bar (`history.replaceState`), keeps the session secret in `sessionStorage` and sends it as `x-pgard-session` from then on. The URL token is no longer accepted by any API route.
  3. A second exchange with the same URL token (a reused link, another tab, a copied link, the browser history) is refused with `409 token_used`, and the page says: "This link was already used. Run the command again to get a new one." / "이미 사용한 링크입니다. 명령을 다시 실행해 새 링크를 받으세요."
     - `409 token_used` is only for the real spent token, compared in constant time (`timingSafeEqual` on equal-length hashes). Any other token gets `401`, so the answer never tells a guesser that a token once existed.
  4. An unused URL token expires after 10 minutes; the launcher then prints how to get a new one (rerun the command).
  5. **A lost exchange race means the link was taken.** If another page exchanged the token first, the user's own page gets `409 token_used`. The server prints a terminal line on every exchange ("Browser connected at 23:41:07."), and the "already used" page adds: "If you did not open it, stop the server (Ctrl+C) and run the command again." / "직접 연 것이 아니라면 서버를 멈추고(Ctrl+C) 명령을 다시 실행하세요."
- **Session secret idle timeout.** The session secret expires after 30 minutes without an API call (the page's own polling counts as use while it is open); after that the page says to rerun the command.
- **Reload: kept working, in that tab only.** A reload of the same tab finds the session secret in `sessionStorage` and continues without the URL token. Opening the link in a new tab, a new window or after closing the tab needs a new link (rerun the command).
  - Why `sessionStorage`: it is scoped to the exact origin, **including the port**, and to the tab, and is gone when the tab closes. A reload is the most common thing a user does on a local page (and what a developer does after every change), so losing the session on reload would strand people for no security gain: the attacker this protects against reads the terminal or the history, not the tab's storage.
  - Known limits, accepted: the browser's **Duplicate tab** copies `sessionStorage`, and **session restore** (reopening closed tabs, or the browser restarting with its tabs) keeps it. Both stay on the same person's browser profile, and the secret is worthless once the server stops (each run makes a new one), and after the idle timeout.
  - Rejected, a cookie: cookies are not isolated by port, so a session cookie for `127.0.0.1:4317` would also be sent to every other local server on `127.0.0.1` (including the dev server PGARD scans).
  - Rejected, `localStorage`: it outlives the tab and the browser restart and is shared by every tab of the origin, which keeps a secret around longer than the session needs.
  - Rejected, memory only: every reload would end the session.
- **One session at a time.** After the exchange, only the holder of the session secret can use the API; a second browser cannot join. The terminal says "Opened in your browser. To open it elsewhere, stop and rerun the command."
- **Unchanged.** `127.0.0.1` only, exact Host check, Origin check, CSP, the project epoch.

### 12.3 Tests (phase 5)

Exchange once, refuse a second exchange (`409` only for the spent token, `401` for any other) and the raw URL token on every route, the terminal line on exchange, reload with the session secret, the idle timeout, expiry of an unused token, masked terminal output and `--print-url`, opener argv per platform (Linux display and SSH rules, the Windows URL check) and the CI / no-terminal fallback, the "already used" page in English and Korean.

### 12.4 As built (#419)

- `apps/local-web/src/server/session/url-session.ts`: the URL token and the session secret are kept only as SHA-256 hashes and compared with `timingSafeEqual` (equal-length digests). `409 token_used` only for the real spent token, `410 token_expired` for the real unused token after 10 minutes, `401 bad_token` for anything else. Session secret: 32 random bytes, `401 session_expired` after 30 minutes without a call, then `401 bad_session`. Missing header: `401 missing_session`. `x-pgard-token` is gone.
- `POST /api/session/exchange` runs after the Host and Origin checks (a write: our exact `Origin` is required) and before the session check; every other route needs `x-pgard-session`.
- The page (`api/client.ts`, `app/Root.tsx`) connects once before rendering (strict mode shares one attempt): the stored secret first (a reload), then the exchange. Any refusal is a whole page in plain English or Korean (`app/ConnectionNotice.tsx`): already used, expired, session ended, no link, not this server, not reachable. A session that ends later (idle timeout) switches to the "session ended" page.
- **Threat: the link on a command line.** Process arguments are visible to other local users (`ps -axww` on macOS, the world-readable `/proc/<pid>/cmdline` on Linux, where `xdg-open` is a shell script whose children carry the argument too). Another user could read the token while the opener runs and exchange it first with a forged `Origin` (Origin only stops browsers). So the link is never an opener argument: it is written into a redirect file (`redirect-file.ts`, the approach of Jupyter's `use_redirect_file`): a new 0700 directory from `mkdtemp`, a 0600 `open-pgard.html` created with `O_EXCL` and no-follow, holding a meta refresh, a `location.replace` and a visible link (the link must match the strict pattern; the markup is escaped). The opener gets only that file's path, which must be exactly our file in our own `pgard-open-` directory. The file is deleted right after the exchange, when the unused link expires (10 minutes) and when the server stops (also on SIGINT and SIGTERM). Not covered: someone who already runs as the same user can read the file, as they could read the terminal.
- Every exchange prints `Browser connected at ...`, and a refused reuse (`409`) prints `Someone tried to reuse the link at ...`, so a lost race is visible in the terminal.
- The opener (`apps/local-web/src/server/open-local-url.ts`) is separate from the GitHub opener: the link inside the file must match `^http://127\.0\.0\.1:\d+/(#token=[A-Za-z0-9_-]+)?$` on every platform (not only Windows), then `/usr/bin/open <file>`, `xdg-open <file>` (only with a display) or `%SystemRoot%\System32\rundll32.exe url.dll,FileProtocolHandler <file>`, with `shell: false`. An SSH session (`SSH_CONNECTION` or `SSH_TTY`) never opens a browser on any platform. The opener's exit code is awaited for 1.5 s: a non-zero exit counts as not opened and prints the full link; the "opened" line adds "If no browser opened, run again with --print-url." `--no-browser` also keeps the local page from opening (it opens nothing), next to the new `--no-open`.
- The terminal text is `launch-output.ts`; the CLI passes `--no-open` and `--print-url` through to the launcher.
