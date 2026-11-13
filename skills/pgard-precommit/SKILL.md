---
name: pgard-precommit
description: Run or set up the PGARD pre-commit check for staged changes, and explain a blocked commit. Use when a commit was stopped by `pgard precommit`, or when the user wants to check staged changes or install the hook. Do not use for full-repository scans (use pgard-scan), for bypassing the hook, or for committing on the user's behalf.
---

# pgard-precommit

Checked against pgard 0.3.0 (`README.md`).

## Safety rules (always apply)

1. **Exit 3 (authorization did not pass):** never relax it. It only happens when the user opted in with `"requireAuthorization": true`. Do not switch to a code-only check unless the user asks for one; say the result would be "authorization not verified".
2. **Exit 4, or any `NOT scanned` line:** report what was not checked. Never call the commit safe or clean.
3. **Never ask for, print, guess or reconstruct secret values.** Work from the redacted findings only. A secret in the staged content is reported by kind and location.
4. **Do not bypass the hook.** Do not run `git commit --no-verify`, change `pgard.config.json` to `warn`, or add suppressions to get a commit through unless the user asks for that specific action. Tell them the option exists and what it costs.
5. **Do not run `pgard login`, touch the keychain, use device codes, or sign in or out.** Those are the user's steps. Never scan a remote service or run `scan web` / `scan all`.
6. **Suggest fixes; do not apply, commit or push them** without the user's confirmation. This includes `git add`, `git commit`, `pgard precommit install` and `pgard precommit uninstall`, which change the repository: ask first.

## Prerequisites

`npm install -g pgard` (Node.js 22.23.4, 24.22.1 or 26.12.1 or a newer patch on the same line), then `pgard doctor` to check the setup. The hook fails closed: without `pgard` on `PATH` it blocks the commit and says so.

## What it checks

- Only the content **staged** for the next commit (read from the Git index, never the working tree), and only what the commit adds or changes.
- Secrets: `PG-SECRET-001` (a new `.env` file, flagged by name) and `PG-SECRET-002` (a credential), plus file-local source rules for JavaScript, TypeScript, Vue and Go. Project-wide rules (missing CSRF protection, unprotected routes, dependencies) run in `pgard scan`, not here.
- By default it is code-only: no sign-in, no network, no keychain; one stderr line says `code-only, authorization not verified`. With `"precommit": { "requireAuthorization": true }` in the staged `pgard.config.json` it uses the full authorization gate and never starts a sign-in itself.
- Skipped by design and named on every run: binary files in a known format, symbolic links, submodules. Large text files (over 1 MiB) and other content that was not read count as "not scanned".

## Block or warn

Set in `pgard.config.json`. The staged copy is the one read, so `git add pgard.config.json` for a change to apply:

```json
{ "precommit": { "mode": "block", "whenNotScanned": "block", "requireAuthorization": false } }
```

- `mode`: `block` (default) exits 1 on a finding and stops the commit; `warn` prints the findings and exits 0. Findings of severity `info`, suppressed findings and baseline findings do not count.
- `whenNotScanned`: what happens when nothing, or not everything, was scanned (an error, a file over the size limit, more than 500 changed files, an unresolved merge conflict; with `requireAuthorization` also not authorized or a timeout). Unset, it equals `mode`. With `block`, such a commit stops (exit 3 when not authorized, only with `requireAuthorization`; 4 for the other cases). With `"warn"`, it goes through with a warning. It is never a silent pass: the output says `NOT scanned` and why.
- An invalid `pgard.config.json` is ignored as a whole and means `block`.

## Exit codes

| Code | Meaning                                                                                                                                                                                                                                                                                                                     |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | The requested scope completed (findings may exist). For `doctor`: the diagnosis completed.                                                                                                                                                                                                                                  |
| 1    | `pgard precommit` in block mode: the staged changes have findings, so the commit is stopped. Only this command returns 1.                                                                                                                                                                                                   |
| 2    | Invalid command, option, value or combination (also `pgard login` without a terminal; a refused `pgard precommit install` or `uninstall`; an unsupported Node.js version).                                                                                                                                                  |
| 3    | Authorization did not pass and nothing was scanned: no approval, a check that could not finish (a network error, or GitHub not answering within 10 s), no GitHub remote, or not a Git repository. Without a terminal and without a saved sign-in this is immediate ("Not signed in"). A code-only scan exits 0 or 4, not 3. |
| 4    | Part of the scan did not run, so the result is partial (for example, no web target was confirmed, or the Git history scan stopped at its time budget), or the report export failed.                                                                                                                                         |
| 5    | Unexpected internal error only (never a failed authorization). Details are hidden; `PGARD_DEBUG=1` shows a sanitized message.                                                                                                                                                                                               |
| 130  | Cancelled by the user.                                                                                                                                                                                                                                                                                                      |
| 143  | Terminated by SIGTERM while the panel view was open.                                                                                                                                                                                                                                                                        |

## Steps

1. Run `pgard precommit` in the repository the user named, after the user has staged their changes (do not stage for them without asking). It reads the index and changes nothing.
2. Read the exit code and the output.
3. **Exit 1 (block):** list each finding by rule id, severity and `file:line`, with redacted evidence only. Then suggest a fix: remove the secret from the staged file, load it from an environment variable, and rotate the credential if it was ever pushed or shared. After the user confirms and edits, they restage and commit.
4. **Exit 3 or 4, or `NOT scanned` lines:** say what was not scanned and why (for example a file over 1 MiB, more than 500 changed files, a merge conflict). Do not call the commit safe. Offer the options (split the change, `"whenNotScanned": "warn"`, `git commit --no-verify` once) and let the user choose.
5. **Exit 0:** say that the staged changes had no new findings in what was scanned, and repeat any `NOT scanned` or "Not scanned by design" lines. A secret hidden inside a skipped binary file is not found.
6. Install the hook only on the user's request: `pgard precommit install` (needs a terminal; refuses an unsafe `core.hooksPath`). For a hook manager such as husky or the pre-commit framework, `pgard precommit snippet` prints the lines. `pgard precommit uninstall` removes the hook. A clean merge commit runs `pre-merge-commit`, which `install` does not write.

## Example

User: "My commit was rejected by pgard."

1. `pgard precommit` exits 1 and prints `PG-SECRET-002` (high) at `src/config.js:4`, evidence redacted.
2. Reply: "The hook blocked the commit (exit 1, `mode: block`). It found a credential (`PG-SECRET-002`, high) at `src/config.js:4`. I have not seen its value and do not need it. Suggested fix: read it from an environment variable instead, and rotate the credential if it was ever shared. Do you want me to edit the file? I will not commit or use `--no-verify` unless you say so."
