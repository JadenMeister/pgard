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
  pgard --help | <command> --help
  pgard --version

The target is always the Git root of the current directory. Every scan re-runs the
authorization gate. Code and results are processed locally; PGARD contacts GitHub
for sign-in and repository metadata only.

${EXIT_CODE_HELP}`,
  project: `Usage:
  pgard project verify

Subcommands:
  verify   show each authorization check with its reason`,
  "project verify": `Usage:
  pgard project verify

Checks the Git repository, GitHub remote, your GitHub identity (device sign-in),
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
in the browser). Results and the session end when you stop the dashboard.

${EXIT_CODE_HELP}`,
  rules: `Usage:
  pgard rules list [--language js|ts|react|vue|go]`,
  "rules list": `Usage:
  pgard rules list [--language js|ts|react|vue|go]

Lists supported rules, the advisory data version and unsupported areas.
Works outside a project.`,
  doctor: `Usage:
  pgard doctor

Checks Node.js, Git, GitHub reachability, local port discovery, whether
PGARD_GITHUB_APP_CLIENT_ID is set and the advisory database. This is a
diagnosis only; it does not authorize scans. Works outside a project.

Exit codes: 0 when the diagnosis completed (problems are listed as [fail] or
[warn]), 5 on an internal error.`,
};

export function getHelpText(topic: HelpTopic): string {
  return HELP_TEXT[topic];
}
