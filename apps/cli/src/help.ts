import type { HelpTopic } from "./options.js";

const EXIT_CODE_HELP = `Exit codes:
  0    requested scope completed (findings may exist)
  2    invalid command, option or value
  3    repository, authorization or contribution check failed
  4    part of the scan or the report export failed
  5    internal error
  130  cancelled`;

const NO_BROWSER_HELP = `  --no-browser             do not open GitHub pages (device sign-in, App
                           install) in the browser; the links are printed.
                           In a terminal, PGARD asks you to press Enter
                           before opening a page`;

const NO_STORE_HELP = `  --no-store               do not keep this scan's result on this computer
                           (same as PGARD_NO_STORE=1); the baseline is then
                           neither read nor applied`;

const REPORT_HELP = `  --report html|pdf|both   save a report (requires --output-dir)
  --output-dir <dir>       existing directory for the report (requires --report);
                           files are never overwritten; a directory inside the
                           Git repository needs explicit confirmation`;

const HELP_TEXT: Record<HelpTopic, string> = {
  main: `pgard - local security checks for GitHub projects you are authorized to scan

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

The target is always the Git root of the current directory. Every scan re-runs the
authorization gate; only the GitHub sign-in is reused. Code and results are
processed locally; PGARD contacts GitHub for sign-in and repository metadata only.
GitHub pages open in the browser automatically when stdout is a terminal; pass
--no-browser to scan, project verify, login or dashboard to only print the links.

${EXIT_CODE_HELP}`,
  project: `Usage:
  pgard project verify

Subcommands:
  verify   show each authorization check with its reason`,
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
  --all-findings           list every finding and location; by default more than
                           5 findings in test, fixture or vendored code are
                           summarized, and groups show up to 3 locations. It
                           also lists every suppressed finding (see
                           pgard.config.json) and every finding in the baseline
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
${NO_BROWSER_HELP}

A finished scan of a repository the gate allowed is stored in this computer's
app-data folder (owner-only, never uploaded): the last 20 scans per repository
for 90 days. Delete them with pgard history clear --all.

If owner approval is the only failed check and the PGARD GitHub App just needs to
be installed, PGARD opens the install page, waits for it, re-runs the full
authorization and continues the scan.

Findings come from the code itself (query statements, server code,
configuration, Git history). Scans never download advisory data and never query
a vulnerability database; "pgard advisories update" is a separate download that
only you start.

Web checks send anonymous GET requests to 127.0.0.1 only, within page, depth and
time limits. GET requests can still change state in some applications.
Authenticated browsing is not available in this MVP.

${EXIT_CODE_HELP}`,
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
  rules: `Usage:
  pgard rules list [--language js|ts|react|vue|go]`,
  "rules list": `Usage:
  pgard rules list [--language js|ts|react|vue|go] [--lang en|ko]

Lists supported rules and unsupported areas.
--language react and vue also include the JavaScript/TypeScript rules.
--lang en|ko shows rule titles in that language (default: PGARD_LANG, then the
system locale, then en).
Works outside a project.`,
  history: `Usage:
  pgard history clear --all | --repo owner/name

Subcommands:
  clear   delete stored scan results`,
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
  doctor: `Usage:
  pgard doctor

Checks Node.js, Git, GitHub reachability, local port discovery, which GitHub
App PGARD signs in with (the built-in PGARD App, or PGARD_GITHUB_APP_CLIENT_ID
as an override), whether a GitHub sign-in is saved in the OS keychain (and for
which account; the token is never shown). This is a diagnosis only; it does
not authorize scans. Works outside a project.

Exit codes: 0 when the diagnosis completed (problems are listed as [fail] or
[warn]), 5 on an internal error.`,
  advisories: `Usage:
  pgard advisories update

Subcommands:
  update   download the public OSV vulnerability data for npm and Go`,
  "advisories update": `Usage:
  pgard advisories update

Downloads the public OSV bulk exports for npm and Go from
https://osv-vulnerabilities.storage.googleapis.com/ (https only, that host only)
and stores a compact copy in PGARD's data directory on this computer. It runs
only when you run this command, never during a scan. Nothing is uploaded: the
request is a plain GET of a fixed file, with no package names, no project data
and no sign-in. The npm export is about 220 MB; the download is verified (zip
structure, per-record checksums, size limit, timeout) and replaces the old data
only when everything checks out. If anything fails, the old data stays.

Exit codes:
  0    all ecosystems updated
  4    at least one ecosystem failed (its previous data is unchanged)
  5    internal error
  130  cancelled`,
  login: `Usage:
  pgard login [--no-browser]

Signs in to GitHub with the device flow (you enter a code on github.com) and
saves the sign-in in the OS keychain: macOS Keychain, Windows Credential Manager
or the Linux Secret Service. It is never written to a file. pgard scan,
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

export function getHelpText(topic: HelpTopic): string {
  return HELP_TEXT[topic];
}
