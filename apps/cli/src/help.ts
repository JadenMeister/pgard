import type { HelpTopic } from "./options.js";

const EXIT_CODE_HELP = `Exit codes:
  0    requested scope completed (findings may exist)
  2    invalid command, option or value
  3    repository, authorization or contribution check failed
  4    part of the scan or the report export failed
  5    internal error
  130  cancelled
  143  terminated by SIGTERM while the panel view was open`;

const NO_BROWSER_HELP = `  --no-browser             do not open GitHub pages (device sign-in, App
                           install) in the browser; the links are printed.
                           In a terminal, PGARD asks you to press Enter
                           before opening a page`;

const NO_STORE_HELP = `  --no-store               do not keep this scan's result on this computer
                           (same as PGARD_NO_STORE=1); the baseline is then
                           neither read nor applied`;

const FULL_HELP = `  --full                   scan everything again; by default code and history
                           build on this repository's last stored scan and only
                           look at what changed (the result says which; web
                           checks are always live)`;

const REPORT_HELP = `  --report html|pdf|both   save a report (requires --output-dir)
  --output-dir <dir>       existing directory for the report (requires --report);
                           files are never overwritten; a directory inside the
                           Git repository needs explicit confirmation`;

type ParentTopic = "project" | "rules" | "history" | "advisories";
type LeafTopic = Exclude<HelpTopic, ParentTopic>;
const HELP_TEXT: Record<LeafTopic, string> = {
  main: `pgard - local security checks for GitHub projects you are authorized to scan

Usage:
  pgard <command> [options]
  pgard help <command> [<subcommand>]   same as pgard <command> --help

Common commands:
  pgard                         interactive menu (arrow keys, Enter, Esc, ?)
  pgard scan                    code and configuration + Git history (the default
                                scan; see "pgard scan --help" for what it does)
  pgard scan code               current code and configuration
  pgard scan history            Git history and tracked files (secrets, risky files)
  pgard report                  build a report from the last stored scan of this
                                repository (no new scan) and open it
  pgard sbom                    write a CycloneDX SBOM of the dependencies in this
                                repository's lockfiles (local files only)
  pgard project verify          check repository, GitHub identity, owner approval,
                                current access and merged contribution
  pgard precommit               check the staged changes for secrets and risky
                                patterns (for a Git pre-commit hook)
  pgard login                   sign in to GitHub once and save it in the OS keychain
  pgard doctor                  diagnose the environment (not an authorization)

Common options:
  --lang en|ko                  language of the screen, progress and rule texts
                                (scan, report, sbom, rules list)
  --format text|json|sarif      scan output (scan); html|pdf (report);
                                cyclonedx-json (sbom)
  --report html|pdf|both        save a report after a scan, with --output-dir DIR
                                (scan only)
  --output-dir DIR              existing directory for saved reports and SBOMs
                                (scan, report, sbom)
  --no-browser                  print GitHub links instead of opening them
                                (scan, project verify, login, dashboard)
  --help                        help for a command, e.g. pgard scan code --help

Advanced commands:
  pgard scan web [--port N]     anonymous read-only checks of a local HTTP service
  pgard scan all [--port N]     code + history + local HTTP service
  pgard dashboard [--target-port N]
                                start the local web dashboard
  pgard rules list [--language js|ts|react|vue|go|java|kotlin|python|php] [--lang en|ko]
                                supported rules and unsupported areas
  pgard history clear --all | --repo owner/name
                                delete stored scan results (all, or one repository)
  pgard baseline set [--from-current] | show | clear
                                keep a scan as this repository's baseline; later
                                scans list matching findings under "In baseline"
  pgard advisories update       download public OSV vulnerability data (npm, Go)
                                to this computer; the only non-GitHub download
  pgard logout                  remove the saved GitHub sign-in from the OS keychain
  pgard --version

Advanced options (pgard <command> --help has the details):
  scan:        --all-findings  --fixes  --panels  --full  --no-store  --report-lang en|ko
               --port N (web, all)
  report:      --no-open
  sbom:        --format cyclonedx-json  --output-dir DIR
  dashboard:   --target-port N
  rules list:  --language <name>
  history clear:     --all  --repo owner/name
  baseline set:      --from-current
  advisories update: --force
  precommit:         install | uninstall | snippet  --lang en|ko

The target is always the Git root of the current directory. Every scan re-runs the
authorization gate; only the GitHub sign-in is reused. Code and results are
processed locally and never uploaded; scans and pgard sbom contact GitHub for
sign-in and authorization metadata only (github.com, api.github.com), including
the owner/name of the repository's GitHub remote and local commit SHAs. The one
other destination is osv-vulnerabilities.storage.googleapis.com, and only when
you run pgard advisories update.
GitHub pages open in the browser automatically when stdout is a terminal; pass
--no-browser to scan, project verify, login or dashboard to only print the links.

${EXIT_CODE_HELP}`,
  "project verify": `Usage:
  pgard project verify [--no-browser]

Checks the Git repository, GitHub remote, your GitHub identity (the sign-in saved
by pgard login, or a device sign-in),
owner approval, your current access and a merged contribution, and shows
passed / failed / unverifiable with a reason for each. The result is not stored;
every scan checks again.

If owner approval fails only because the PGARD GitHub App is not installed for
this repository and you may be able to install it (you own the personal account,
or GitHub shows you as an owner of the organization or cannot show your role
yet), PGARD opens the App's install page, waits up to
10 minutes for the installation and then runs all five checks again. Installing
the App is the owner's approval; PGARD cannot install it for you.

Options:
${NO_BROWSER_HELP}

${EXIT_CODE_HELP}`,
  scan: `Usage:
  pgard scan [code|history|web|all] [options]

With no options, pgard scan checks the current code and configuration and the Git
history of this repository (the same as "pgard scan" in the menu), not a local web
service. The result is printed as text in your language (a full-screen panel view
opens by itself in a terminal), nothing is written to the repository and no report
file is saved. A finished scan of a verified repository is stored locally (see
below) and the next scan only looks at what changed since it; --full scans
everything again, --no-store keeps nothing.

Scopes:
  (none)    code + history
  code      current code and configuration
  history   Git history and tracked files
  web       a local HTTP service on 127.0.0.1 you confirm
  all       code + history + web (partial if no web target is confirmed)

Options:
  --port N                 local service port 1-65535 (web and all only). You
                           still confirm the service identity with y/N.
${REPORT_HELP}
  --all-findings           list every finding in full (evidence, fix,
                           standards, every location). In a terminal the
                           default is compact: critical and high first, at most
                           10 groups of one or two lines, then "+N more"; test
                           and vendored code is counted, with its critical and
                           high findings and secrets listed. Not in a terminal
                           (pipe, file) the text is always the full form. It
                           also lists every suppressed finding (see
                           pgard.config.json) and every finding in the baseline
  --fixes                  also show a suggested-fix diff under the findings that
                           have one (implies --all-findings). A suggestion to
                           review: PGARD never applies it, writes to your files
                           or checks that it compiles or keeps behaviour
  --panels                 open the read-only full-screen view (summary, charts,
                           coverage, findings; keys: Tab, arrows, ? help, Esc
                           back, Ctrl+D leaves) after the text result. In a
                           terminal pgard scan already opens it by itself, but
                           not when CI, GITHUB_ACTIONS, BUILDKITE, TF_BUILD or
                           JENKINS_URL is set, or TERM=dumb. PGARD_PANELS=off
                           (also 0, false, no) turns it off: use it for script,
                           expect, VS Code tasks and docker run -it. --panels
                           still forces it (not with TERM=dumb); so does
                           PGARD_PANELS=on in CI. Never opens without a
                           terminal. Not with --format json or sarif. pgard
                           dashboard is the separate local web app
  --format text|json|sarif json prints only the redacted result (schema in
                           docs/RESULT_SCHEMA.md) to stdout; sarif prints the
                           same result as SARIF 2.1.0 (for GitHub code
                           scanning; PGARD uploads nothing). Progress and
                           messages go to stderr. With web checks it needs --port
                           (prompts go to stderr). Exit codes are unchanged
  --lang en|ko             language of the result screen, progress lines and rule
                           texts (default: PGARD_LANG, then the system locale,
                           then en). JSON and SARIF output are always English
  --report-lang en|ko      language of saved reports (default: the
                           --lang language)
${NO_STORE_HELP}
${FULL_HELP}
${NO_BROWSER_HELP}

A finished scan of a repository the gate allowed is stored in this computer's
app-data folder (owner-only, never uploaded): the last 20 scans per repository
for 90 days. Delete them with pgard history clear --all.

If owner approval is the only failed check and the PGARD GitHub App just needs to
be installed, PGARD opens the install page, waits for it, re-runs the full
authorization and continues the scan.

Findings come from the code itself (query statements, server code,
configuration, Git history) and, for npm and Go lockfiles, from a version match
against the OSV data you downloaded. Scans never download advisory data and
never query a vulnerability database; "pgard advisories update" is a separate
download that only you start. Without that data the dependency areas are
reported as not tested. A match means the version is in an advisory's affected
range, not that the vulnerable code is reachable or exploitable.

Web checks send anonymous GET requests to 127.0.0.1 only, within page, depth and
time limits. GET requests can still change state in some applications.
Authenticated browsing is not available in this MVP.

${EXIT_CODE_HELP}`,
  report: `Usage:
  pgard report [--format html|pdf] [--output-dir DIR] [--no-open] [--lang en|ko]

Builds an HTML (default) or PDF report from the last scan stored for this
repository and opens it. It does not scan again and uploads nothing; the
repository checks contact GitHub, as for pgard baseline.
The repository is identified the way pgard baseline and the panel view do it: the
repository checks run first, and only a result stored under this repository's
GitHub id is read. If the repository cannot be verified, nothing is read (exit 3).

Options:
  --format html|pdf        report format (default html)
  --output-dir DIR         existing directory for the report. Files have fixed
                           names (pgard-report-<time>-<scan>), are created with
                           mode 0600 and never overwritten; a directory inside
                           the Git repository needs explicit confirmation.
                           Without it, each run writes into a new private
                           directory (mode 0700) under the system temporary
                           directory and prints its path. Browsers installed as
                           snap packages on Linux may not be able to read /tmp:
                           use --output-dir ~/Downloads (or similar) then
  --no-open                write the file and print its path without opening it.
                           Without a terminal, and when CI, GITHUB_ACTIONS,
                           BUILDKITE, TF_BUILD or JENKINS_URL is set or TERM=dumb,
                           the report is never opened
  --lang en|ko             language of messages and of the report (default:
                           PGARD_LANG, then the system locale, then en)

If HEAD has moved since the stored scan, a one-line note says so; the report
header shows the scan time and the commit it covers.

Exit codes:
  0    report written
  2    invalid option, no stored scan (run pgard scan first), or PGARD_NO_STORE=1
  3    not a Git repository, or the repository could not be verified
  4    the report could not be written
  5    internal error
  130  cancelled
`,
  sbom: `Usage:
  pgard sbom [--format cyclonedx-json] [--output-dir DIR] [--lang en|ko]

Writes a CycloneDX 1.6 JSON software bill of materials (SBOM) of the packages
listed in this repository's lockfiles (package-lock.json, npm-shrinkwrap.json,
pnpm-lock.yaml, yarn.lock, go.mod/go.sum): name, version, package URL (purl) and
the lockfiles each came from. Direct dependencies are linked from the repository
component; PGARD's parsers do not read the dev scope or the links between other
packages (some lockfiles record them), so no scope is written and the graph is
marked direct-only. Every package is listed by name and version as a registry
package: a dependency resolved from git, a tarball URL or a file: path is not
told apart yet. It does not scan, uploads nothing and runs no
package manager or build tool. Lockfiles it cannot read, or does not support
yet, are listed as pgard:unparsed-lockfile properties (and the SBOM is marked
incomplete), so a missing package is never mistaken for a clean one.

Reading a repository's files needs the same authorization as the other
repository commands: the repository checks (which contact GitHub) run first, as
for pgard report, and nothing is read if they fail (exit 3).

Options:
  --format cyclonedx-json  the only format (default)
  --output-dir DIR         existing directory for the SBOM. The file is named
                           pgard-sbom-<time>-<commit>.cdx.json, is created with
                           mode 0600 and never overwritten; a directory inside
                           the Git repository needs explicit confirmation.
                           Without it, each run writes into a new private
                           directory (mode 0700) under the system temporary
                           directory and prints its path
  --lang en|ko             language of messages (default: PGARD_LANG, then the
                           system locale, then en)

Exit codes:
  0    SBOM written (it may be marked incomplete; a warning says so)
  2    invalid option, or the directory is missing or not confirmed
  3    not a Git repository, or the repository could not be verified
  4    the SBOM could not be written
  5    internal error
  130  cancelled
`,
  dashboard: `Usage:
  pgard dashboard [--target-port N] [--no-browser]

Starts the local web dashboard on a free 127.0.0.1 port and prints its private
URL. --target-port pre-selects the local service to check (you still confirm it
in the browser). The dashboard reuses the GitHub sign-in saved in the OS
keychain; the token stays in the dashboard server and never reaches the
browser. Dashboard scans are not stored: their results and the session end when
you stop the dashboard.
The dashboard opens the GitHub sign-in page when a device code is needed
(unless --no-browser) and shows an install button when the PGARD GitHub App is
not installed for this repository.

${EXIT_CODE_HELP}`,
  "rules list": `Usage:
  pgard rules list [--language js|ts|react|vue|go|java|kotlin|python|php] [--lang en|ko]

Lists supported rules and unsupported areas.
--language react and vue also include the JavaScript/TypeScript rules.
--lang en|ko shows rule titles in that language (default: PGARD_LANG, then the
system locale, then en).
Works outside a project.`,
  "history clear": `Usage:
  pgard history clear --all | --repo owner/name

Deletes the scan results that pgard scan stored in this computer's app-data
folder. One of the two options is required: --all deletes every repository's
results; --repo deletes the results of one repository, matched by the owner/name
stored in them (after a rename or transfer, give the name the results were
stored under). A repository's baseline (pgard baseline) is deleted together
with its results. Nothing is uploaded and no sign-in is needed. Stop storing with --no-store
on pgard scan or PGARD_NO_STORE=1.

${EXIT_CODE_HELP}`,
  baseline: `Usage:
  pgard baseline set [--from-current]
  pgard baseline show
  pgard baseline clear

A baseline is a scan of this repository that you accept as the reference, kept in
the local result store (same folder, permissions and --no-store rules as scan
results). Later scans compare against it with the same finding identity as the
"Since the last scan" line: findings that match it are listed apart under
"In baseline (N)" and the new ones are highlighted. Nothing is hidden: the counts
are always shown, --all-findings lists the baseline findings, and the status and
exit code do not change.
  set                 use the newest stored scan of this repository (no new scan)
  set --from-current  scan code and history now and use that scan
  show                when it was set, from which scan, and how many findings
  clear               delete the baseline
The baseline is kept per verified repository, so these commands run the
authorization gate first. pgard scan --no-store and PGARD_NO_STORE=1 neither read
nor apply a baseline, and the baseline commands refuse to run with PGARD_NO_STORE=1.
pgard history clear also deletes the baseline.

${EXIT_CODE_HELP}`,
  precommit: `Usage:
  pgard precommit [--lang en|ko]        check the staged changes
  pgard precommit install               write .git/hooks/pre-commit
  pgard precommit uninstall             remove that hook (only if PGARD wrote it)
  pgard precommit snippet               print lines for the pre-commit framework or husky

Checks what is staged for the next commit, read from the Git index (never the working
tree), for secrets (PG-SECRET-001, PG-SECRET-002) and the file-local source rules
(JavaScript, TypeScript, Vue, Go). Only what the commit adds or changes is reported (a
changed private key body counts even under an unchanged header). A new .env file is
reported by its name whatever it holds. Deleted files have nothing to scan. Clearly
binary files (a known file signature such as PNG, ZIP or ELF, or binary content at both
ends; of any size) and symbolic links are skipped by design and listed by name on every
run. Text with stray NUL bytes, UTF-16 text (with or without a byte order mark) and a
large file that only starts like a binary are not skipped: they are scanned, or, when over
1 MiB, reported as not scanned. Rules that need
the whole project (missing CSRF protection, unprotected routes, dependencies) run in
pgard scan. Suppressions and the baseline apply. Staged content stays on this computer;
like a scan it contacts GitHub (github.com, api.github.com) for authorization metadata
only.

Authorization is the same gate as pgard scan: all five checks, every time, nothing
cached. It needs a saved sign-in (pgard login) because a hook never starts a sign-in.
If the gate does not allow, or the check cannot finish, the staged changes were NOT
scanned and PGARD says so.

Mode is set in pgard.config.json, read from the version in the Git index (the one
being committed; an untracked file is not used, run git add). Suppressions and exclude
come from the staged copy too, and a note says when the working-tree file differs (only
testDirectories is read from the working tree):
  "precommit": { "mode": "block" | "warn", "whenNotScanned": "block" | "warn" }
  block (default)   findings stop the commit (exit 1)
  warn              findings are printed, the commit goes on (exit 0)
  whenNotScanned    what happens when nothing, or not everything, was scanned
                    (not authorized, error, timeout, a text file over 1 MiB,
                    more than 500 changed files, 5 s analysis cap). Default: the
                    same as mode, so a blocking hook blocks. An invalid config
                    means block.
Limits: authorization up to 15 s (PGARD_PRECOMMIT_TIMEOUT_MS=1000..120000 changes
it), then reading and checking the staged changes up to 5 s (typically well under
1 s): text files up to 1 MiB, up to 500 changed files, 16 MiB in total. Findings of
severity info do not block.

A clean merge commit runs pre-merge-commit, not pre-commit (see snippet). A merge is
compared with HEAD (ours), so what the other branch brings counts as added.

install writes only into this repository's own .git/hooks (with core.hooksPath and
symbolic links checked), never overwrites a hook PGARD did not write unless you confirm
in a terminal (the old hook is kept as pre-commit.pgard-backup), and refuses without a
terminal. Skip a hook once with git commit --no-verify.

Exit codes:
  0    nothing blocks the commit (clean, warn mode, or nothing scanned with
       whenNotScanned: warn, which is said on screen)
  1    findings in block mode (a crash of Node itself also exits 1; both block)
  2    invalid command, or install/uninstall refused
  3    not authorized (nothing scanned) and whenNotScanned blocks
  4    other cases where not everything was scanned, and whenNotScanned blocks
  5    internal error
  130  cancelled`,
  doctor: `Usage:
  pgard doctor

Checks Node.js, Git, GitHub reachability, local port discovery, which GitHub
App PGARD signs in with (the built-in PGARD App, or PGARD_GITHUB_APP_CLIENT_ID
as an override), whether a GitHub sign-in is saved in the OS keychain (and for
which account; the token is never shown), and the downloaded advisory data
(present or missing, age, stale after 7 days, data version, store path; read from
local files). Its only network request is an unauthenticated HEAD to
api.github.com. This is a diagnosis only; it does not authorize scans. Works
outside a project.

Exit codes: 0 when the diagnosis completed (problems are listed as [fail] or
[warn]), 5 on an internal error.`,
  "advisories update": `Usage:
  pgard advisories update [--force]

Downloads the public OSV bulk exports for npm and Go from
https://osv-vulnerabilities.storage.googleapis.com/ (https only, that host only)
and stores a compact copy in PGARD's data directory on this computer. It runs
only when you run this command, never during a scan. Nothing is uploaded: the
request is a plain GET of a fixed file, with no package names, no project data
and no sign-in. The npm export is about 220 MB; the download is verified (zip
structure, per-record checksums, size limit, timeout) and replaces the old data
only when everything checks out. If anything fails, the old data stays. OSV
publishes no checksum to compare against, so integrity rests on https to that
host (trust on first use): the checks detect damage and truncation, not tampering.

A download whose newest record is older than the installed data, or that holds
fewer than half as many records, is refused and the installed data stays (this
guards against a replayed old archive). --force accepts it anyway.

Exit codes:
  0    all ecosystems updated
  4    at least one ecosystem failed (its previous data is unchanged)
  5    internal error
  130  cancelled`,
  login: `Usage:
  pgard login [--no-browser]

Signs in to GitHub with the device flow (you enter a code on github.com) and
saves the sign-in in the OS keychain: macOS Keychain, Windows Credential Manager
or the Linux Secret Service. It is never written to a file. Login contacts only
github.com and api.github.com; your code and results are never sent. pgard scan,
pgard project verify and pgard dashboard then reuse it without a device code;
an expired token is refreshed automatically when the GitHub App issues refresh
tokens. Every scan still runs all five authorization checks against GitHub.
Running login again replaces the saved sign-in (e.g. to switch accounts).
PGARD signs in as the built-in PGARD GitHub App; set PGARD_GITHUB_APP_CLIENT_ID
only to use another App (a fork or a self-registered App). A value that is not
a valid client id blocks sign-in (exit 3); it never falls back to the built-in
App. PGARD_GITHUB_APP_SLUG names that App's install page for the guided install
(lowercase letters, digits and "-"); a malformed value also blocks sign-in.
--no-browser prints the sign-in page without opening it.
Works outside a project.

Exit codes:
  0    signed in and saved
  3    GitHub sign-in failed, or PGARD_GITHUB_APP_CLIENT_ID is not a valid
       client id
  4    no OS keychain is available, or it did not save; nothing was saved
  5    internal error
  130  cancelled`,
  logout: `Usage:
  pgard logout

Removes the GitHub sign-in saved for this GitHub App from the OS keychain. PGARD
cannot revoke the token at GitHub (that needs the App's client secret); revoke
it at https://github.com/settings/apps/authorizations if needed. Works outside a
project.

Exit codes:
  0    removed, or nothing was saved
  3    PGARD_GITHUB_APP_CLIENT_ID is not a valid client id; nothing was removed
  4    no OS keychain is available; nothing was removed
  5    internal error`,
};

/** Command groups with a single subcommand show that subcommand's help. */
const SAME_AS: Record<ParentTopic, LeafTopic> = {
  project: "project verify",
  rules: "rules list",
  history: "history clear",
  advisories: "advisories update",
};

export function getHelpText(topic: HelpTopic): string {
  return HELP_TEXT[topic in SAME_AS ? SAME_AS[topic as ParentTopic] : (topic as LeafTopic)];
}
