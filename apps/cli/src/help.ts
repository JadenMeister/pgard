import type { HelpTopic } from "./options.js";

const EXIT_CODE_HELP = `Exit codes:
  0    requested scope completed (findings may exist)
  2    invalid command, option or value
  3    repository, authorization or contribution check failed
  4    part of the scan or the report export failed
  5    internal error
  130  cancelled`;

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

The target is always the Git root of the current directory. Every scan re-runs the
authorization gate; only the GitHub sign-in is reused. Code and results are
processed locally; PGARD contacts GitHub for sign-in and repository metadata only.

${EXIT_CODE_HELP}`,
  project: `Usage:
  pgard project verify

Subcommands:
  verify   show each authorization check with its reason`,
  "project verify": `Usage:
  pgard project verify

Checks the Git repository, GitHub remote, your GitHub identity (the sign-in saved
by pgard login, or a device sign-in),
owner approval, your current access and a merged contribution, and shows
passed / failed / unverifiable with a reason for each. The result is not stored;
every scan checks again.

${EXIT_CODE_HELP}`,
  scan: `Usage:
  pgard scan [code|history|web|all] [options]

Scopes:
  (none)    code + history
  code      current code, configuration and dependencies
  history   Git history and tracked files
  web       a local HTTP service on 127.0.0.1 you confirm
  all       code + history + web (partial if no web target is confirmed)

Options:
  --port N                 local service port 1-65535 (web and all only). You
                           still confirm the service identity with y/N.
${REPORT_HELP}

Web checks send anonymous GET requests to 127.0.0.1 only, within page, depth and
time limits. GET requests can still change state in some applications.
Authenticated browsing is not available in this MVP.

${EXIT_CODE_HELP}`,
  dashboard: `Usage:
  pgard dashboard [--target-port N]

Starts the local web dashboard on a free 127.0.0.1 port and prints its private
URL. --target-port pre-selects the local service to check (you still confirm it
in the browser). The dashboard reuses the GitHub sign-in saved in the OS
keychain; the token stays in the dashboard server and never reaches the
browser. Results and the session end when you stop the dashboard.

${EXIT_CODE_HELP}`,
  rules: `Usage:
  pgard rules list [--language js|ts|react|vue|go]`,
  "rules list": `Usage:
  pgard rules list [--language js|ts|react|vue|go]

Lists supported rules, the advisory data version and unsupported areas.
--language react and vue also include the JavaScript/TypeScript rules.
Works outside a project.`,
  doctor: `Usage:
  pgard doctor

Checks Node.js, Git, GitHub reachability, local port discovery, which GitHub
App PGARD signs in with (the built-in PGARD App, or PGARD_GITHUB_APP_CLIENT_ID
as an override), whether a GitHub sign-in is saved in the OS keychain (and for
which account; the token is never shown) and the advisory database. This is a
diagnosis only; it does not authorize scans. Works outside a project.

Exit codes: 0 when the diagnosis completed (problems are listed as [fail] or
[warn]), 5 on an internal error.`,
  login: `Usage:
  pgard login

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
App.
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
