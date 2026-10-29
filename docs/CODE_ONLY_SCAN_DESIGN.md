# Security design: code-only scans without GitHub approval, and the one-screen web flow

> [한국어](CODE_ONLY_SCAN_DESIGN.ko.md) translation available. This English file is the reference; the translation follows it.

> **Status: proposal with a working prototype, for the owner's sign-off ([#414](https://github.com/JadenMeister/pgard/issues/414)).**
>
> - **Nothing ships yet.** The CLI is unchanged. `pgard web` is unchanged unless you set `PGARD_WEB_PROTOTYPE=code-only`. The README remains the source of truth for current behaviour.
> - **Decisions for the owner** are marked **[Owner decision]**. Each one gives a recommendation; section 11 lists all of them together.

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

- The prototype adds `scanWorkingTreeSecrets` (`packages/scan-core/src/working-tree-secrets.ts`).
  - It uses the same detection as `pgard precommit` (`scanStagedSecrets`, every line counted as new).
  - It never follows symbolic links.
  - It skips `.git` and `node_modules`.
  - It reads files up to 1 MiB and skips binary files.
  - It has file-count and depth limits; when a limit is hit the area is `partial`.
  - It never puts a value in a finding.
- **Production follow-up:** the rule titles say "Secret in a tracked file" and "Environment file committed to Git". For a code-only finding this is wrong. Production needs a code-only wording, either two new rule ids or a title variant. The prototype screenshots show the old titles.

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
  "reason": "no_approval"
}
```

- **`mode`.**
  - `"authorized"`: the gate passed.
  - `"code_only"`: no gate ran.
  - The field is absent in results of 1.6 and older, and a reader treats absent as `"authorized"`, because older PGARD only wrote results after the gate passed.
- **`authorization`.** `"verified"` or `"not_verified"`. This is the coordinator's `authorization: "not_verified"`. It sits in a new object, because retyping the existing `authorization` object would be a major change.
- **`reason`.** An open-ended code:
  - `no_approval` (the gate did not pass),
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
- **The version history note** in `RESULT_SCHEMA.md` states this cross-field rule: in 1.7, `decision: "blocked"` together with a status other than `blocked` means `code_only`.

### 4.2 SARIF

- `runs[0].properties.pgard.scanBasis` carries the same object.
- `runs[0].invocations[0].toolExecutionNotifications[]` carries one `warning`: "Code-only scan: authorization was not verified. Git history and web checks did not run."
- Uploaders that show notifications (GitHub code scanning does) show it next to the results.

### 4.3 Text, reports and the dashboard

- **Terminal.** The first line of the result is `! Code-only scan: authorization not verified (current files only; no Git history, no web checks, not saved).`, followed by one line on how to get an authorized scan.
- **HTML and PDF report.** Every page carries a banner, and the cover says "Not authorized: code-only scan". There is no "verified" wording. The prototype refuses export until this exists (`409 code_only_result`).
- **Web.**
  - The results card always starts with the label **"Not authorized · code only" / "권한 미확인 · 코드만"** and a short explanation.
  - The label cannot be dismissed while the result is on screen.
  - Screenshot: `*-6-not-authorized-label.png`.

## 5. CLI behaviour

**[Owner decision D1] What `pgard scan` does without approval.**

**Recommendation:** code-only by default for the `code` scope, with a clear note. Strict mode is opt-in. This gives "just works" and never implies proof.

| Command                                   | Today                               | Proposed                                                                                                                                                                                                                                                                                                      |
| ----------------------------------------- | ----------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `pgard scan code`                         | Gate; blocked → exit 3, no analysis | **Runs code-only** in any folder (no Git and no GitHub needed), never signs in, and prints the code-only line. Exit 0 / 4 from code coverage. An authorized code scan is asked for with `--require-authorization` (next row).                                                                                 |
| `pgard scan code --require-authorization` | n/a                                 | Today's behaviour: the gate runs first; allowed → an authorized scan (stored as today); blocked → exit 3, no analysis. For people and wrappers that want proof.                                                                                                                                               |
| `pgard scan history`, `scan web`          | Gate                                | **Unchanged** (exit 3 when blocked). The blocked message adds: "`pgard scan code` checks the current files without approval."                                                                                                                                                                                 |
| `pgard scan all`                          | Gate                                | **[Owner decision D2]** Recommendation: **unchanged** (gate; blocked → exit 3, plus the same hint). Alternative: run code-only for `code`, mark `history` and `web` `not_tested` ("needs owner approval"), exit 4. The first keeps "all" honest; the second is friendlier but hides a block behind a partial. |
| Interactive menu (`pgard`)                | Guided sign-in and App install      | The first choice becomes "Scan the current files (code only)". Sign-in and App install are offered afterwards as "Also scan Git history".                                                                                                                                                                     |
| `pgard project verify`                    | Gate only                           | Unchanged. One added line when blocked: "Without approval, `pgard scan code` runs a code-only scan of the current files."                                                                                                                                                                                     |
| `pgard doctor`                            | —                                   | One `[info]` row: "Scans without owner approval run code-only (current files, not saved)."                                                                                                                                                                                                                    |
| `pgard report`, `baseline`, `sbom`, trend | Gated                               | **Unchanged** (they read stored results or claim a repository). `sbom` reads lockfiles only, like the code-only dependency check, so it could follow the same rule later; that is out of scope here.                                                                                                          |

- **Exit codes.** No new code.
  - A code-only scan exits 0 (completed, findings may exist) or 4 (partial), like any scan.
  - Exit 3 stays "blocked by the gate" and appears only when the user asked for authorization (`--require-authorization`, `history`, `web`, `all`).
- **`--format json|sarif`.** Prints the code-only result with `scanBasis` (section 4). Stdout still holds exactly one document.
- **Flags.** One new flag, `--require-authorization` (`code` only; the other scopes always require it). `--code-only` is not needed, because code-only is the default for `code`.

### 5.1 `pgard precommit` (M10-1, #408)

- `pgard precommit` checks **staged changes only**, never history.
- It already reads only the index, which holds the user's own content about to be committed.
- Today it runs the full gate, so without a saved sign-in "the gate blocks and nothing is scanned" (README).

**[Owner decision D3] Recommendation: run `pgard precommit` code-only, always, with no gate and no network.**

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

**[Owner decision D4] Recommendation: both get a code-only scan.** This matches the owner's intent and section 3.2: the gate's evidence is absent, but code-only needs none of it.

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
  - Windows: `powershell.exe -NoProfile -NonInteractive -STA -Command` with `System.Windows.Forms.FolderBrowserDialog`.
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

| Key              | English                                                                                                                                                                    | 한국어                                                                                                                                                                           |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Title            | Scan a project folder                                                                                                                                                      | 프로젝트 폴더 검사                                                                                                                                                               |
| Lead             | PGARD checks the files in a folder on this computer for leaked secrets, risky code and known-vulnerable dependencies.                                                      | PGARD는 이 컴퓨터에 있는 폴더의 파일에서 유출된 비밀값, 위험한 코드, 알려진 취약 의존성을 찾습니다.                                                                              |
| Steps            | Choose a folder · Press Scan · Fix what it finds                                                                                                                           | 폴더 선택 · 검사 누르기 · 찾은 문제 고치기                                                                                                                                       |
| Folder hint      | Choose the project's folder, or paste its path.                                                                                                                            | 프로젝트 폴더를 선택하거나 경로를 붙여 넣으세요.                                                                                                                                 |
| Button           | Choose folder                                                                                                                                                              | 폴더 선택                                                                                                                                                                        |
| Paste box        | Or paste the folder's path · Check                                                                                                                                         | 또는 폴더 경로 붙여 넣기 · 확인                                                                                                                                                  |
| No dialog        | This computer has no folder window PGARD can open. Paste the folder's path below instead.                                                                                  | 이 컴퓨터에는 PGARD가 열 수 있는 폴더 선택 창이 없습니다. 아래에 폴더 경로를 붙여 넣으세요.                                                                                      |
| No Git (D4)      | Not a Git repository: the files are scanned as they are.                                                                                                                   | Git 저장소가 아닙니다. 파일을 있는 그대로 검사합니다.                                                                                                                            |
| Refusal example  | This is your home folder or a system folder, not a project. Choose the project's own folder, for example ~/code/my-app.                                                    | 홈 폴더나 시스템 폴더이며 프로젝트 폴더가 아닙니다. 프로젝트 자체의 폴더를 선택하세요. 예: ~/code/my-app                                                                         |
| Scan explanation | Reads the current files only: secrets, risky code patterns and dependencies. No Git history, nothing leaves this computer and nothing is saved.                            | 현재 파일만 읽습니다: 비밀값, 위험한 코드 패턴, 의존성. Git 기록은 읽지 않고, 이 컴퓨터 밖으로 아무것도 보내지 않으며, 아무것도 저장하지 않습니다.                               |
| Badge            | Not authorized · code only                                                                                                                                                 | 권한 미확인 · 코드만                                                                                                                                                             |
| Badge text       | This is a code-only scan of the files on this computer. PGARD did not prove that you may scan this repository, so Git history, local web checks and saved results are off. | 이 결과는 이 컴퓨터에 있는 파일만 검사한 코드 전용 검사입니다. 이 저장소를 검사해도 된다는 권한을 PGARD가 확인하지 않았으므로 Git 기록, 로컬 웹 검사, 결과 저장은 꺼져 있습니다. |
| Upgrade link     | Connect GitHub to also scan Git history. Optional: opens the full dashboard, which asks for GitHub sign-in and owner approval.                                             | GitHub 연결하고 Git 기록도 검사. 선택 사항: GitHub 로그인과 소유자 승인을 요청하는 전체 대시보드를 엽니다.                                                                       |

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

**[Owner decision D5] Export of code-only results.** Recommendation: allow HTML and PDF export with a "Not authorized: code-only scan" banner on every page, because the file is the user's own local output, like `--format json`. Alternative: no export without approval. The prototype refuses export for now.

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

1. **This PR.** Design and prototype.
   - `runCodeOnlyScan` in scan-core.
   - The working-tree secrets pass.
   - `POST /api/code-scan` behind `PGARD_WEB_PROTOTYPE=code-only`.
   - The simple screen.
   - A dev preview server.
   - No CLI change and no schema change.
2. **Result contract (1.7).**
   - `scanBasis` in findings, the reader, SARIF and report banners.
   - Store refusal of `code_only`.
   - Code-only rule titles for the secrets pass.
   - `RESULT_SCHEMA.md`.
3. **CLI.**
   - `pgard scan code` code-only by default, `--require-authorization`, the terminal line, `project verify` and `doctor` rows, README.
   - `pgard precommit` per D3.
4. **Picker for any folder.** The OS folder dialog and the paste box (section 6.1), non-Git and no-remote folders for code-only (section 6), and `pgard dashboard` for any folder.
5. **Web, production.**
   - The one-screen flow becomes the default `pgard web`.
   - The prototype flag is removed.
   - The full dashboard becomes the authorized flow behind the upgrade link.
   - Filters move under More.
   - i18n moves into the catalogs.
   - Tests.
6. **Independent security review** of phases 2–5 (issue plan step 3), before release.

## 10. The prototype in this PR

- **Real.**
  - The OS folder dialog (macOS `osascript`, Windows PowerShell, Linux `zenity`/`kdialog`) and the paste box, resolved and checked in the real inspector child process (realpath, ownership, write bits, display safety), then the confirm and the re-check before the scan.
  - Folders with no GitHub remote and non-Git folders get a code-only scan (D4).
  - The code-only scan (source rules, dependencies against the on-disk OSV data, and the new secrets pass) on the real folder.
  - The redaction.
  - The token, Host and Origin checks, and `127.0.0.1` only.
- **Not real yet.**
  - The JSON/SARIF `scanBasis` field. The server marks the result with `codeOnly: true` in `GET /api/scan`, not in the result.
  - The report banner. Export is refused.
  - The upgrade link opens today's full dashboard.
- **Never.**
  - The prototype route makes no GitHub call. It is a 404 unless the simple screen is on, and the simple screen is never on in fixed mode.
  - `POST /api/scan` (the gate) is unchanged.
- **Tests.**
  - `packages/scan-core/src/run-code-only.test.ts`: no gate, no history, labelled result.
  - `packages/scan-core/src/working-tree-secrets.test.ts`: secrets on disk, `.env`, links not followed, no Git, no value in output.
  - `apps/local-web/src/server/code-scan-prototype.test.ts`: 404 when off, never on in fixed mode, token, Host and Origin checks, `no_project`, identity re-check, export refused.
  - `apps/local-web/src/server/choose-folder-prototype.test.ts`: dialog and paste routes (404 when off, token and Origin, one dialog at a time, cancel and shutdown kill the dialog, unavailable, refusals with fixes, `~` expansion), a non-Git folder is code-only only (`409 code_only_project` on verify and `POST /api/scan`), the folder re-check before the scan, and the fixed dialog argv per platform.
  - `apps/local-web/src/server/picker/resolve-folder.test.ts`: the `resolve` job on real folders (GitHub repository, no Git, symbolic link, group-writable, outside home, refused paths) and its message validation.

## 11. Decisions for the owner

| #   | Question                                   | Recommendation                                                                              |
| --- | ------------------------------------------ | ------------------------------------------------------------------------------------------- |
| D1  | `pgard scan code` without approval         | Code-only by default with a clear line; `--require-authorization` restores exit 3.          |
| D2  | `pgard scan all` without approval          | Unchanged (blocked, exit 3), with a hint to run `scan code`.                                |
| D3  | `pgard precommit`                          | Always code-only, with no gate and no network; opt-in `requireAuthorization` in the config. |
| D4  | No GitHub remote / not a Git repository    | Both get a code-only scan.                                                                  |
| D5  | Export of code-only results                | Allowed, with a "not authorized" banner on every page.                                      |
| D6  | The one-screen layout and copy (section 7) | Accept as shown in the prototype screenshots, or mark what to change.                       |
