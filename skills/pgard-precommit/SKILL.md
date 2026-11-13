---
name: pgard-precommit
description: Run or set up the PGARD pre-commit check for staged changes, and explain a blocked commit. Use when a commit was stopped by `pgard precommit`, or when the user wants to check staged changes or install the hook. Do not use for full-repository scans (use pgard-scan), for bypassing the hook, or for committing on the user's behalf.
---

# pgard-precommit

Checked against pgard 0.3.0 (`README.md` and `pgard precommit --help`). Run `pgard --version` first; if it differs, re-check with `pgard precommit --help`.

## Safety rules (always apply)

1. **Exit 3 (authorization did not pass):** never relax it. Do not switch to a code-only check unless the user asks; tell them it exists, the user chooses, and the result would be "authorization not verified".
2. **Exit 4, or any `NOT scanned` line:** report what was not checked. Never call the commit safe or clean.
3. **Never ask for, print, guess or reconstruct secret values.** Work from the redacted findings only. A secret in the staged content is reported by kind and location.
4. **Do not bypass the hook.** Do not run `git commit --no-verify`, change `pgard.config.json` to `warn`, or add suppressions to get a commit through. If the user asks for `--no-verify`, say what would be committed (a secret in a block case ends up in Git history) and confirm once more before anything runs.
5. **Do not run `pgard login` or `pgard logout`, use device codes, or sign in or out.** Those are the user's steps. Do not read, export or change keychain entries yourself (`security`, `secret-tool`, `cmdkey` and the like). pgard reading its own saved sign-in is normal. Never scan a remote service. Do not run `scan web` or `scan all`, even for `127.0.0.1`: they need the user's own y/N confirmation, so tell the user to run them.
6. **Suggest fixes; do not apply, commit or push them** without the user's confirmation. This includes `git add`, `git commit`, `pgard precommit install` and `pgard precommit uninstall`, which change the repository: ask first.
7. **Secrets:** editing the flagged line puts the value into your context. Suggest that the user makes the change. If you make it, never quote the value in an answer, a diff or a commit message. Rotating the key and cleaning Git history are always the user's job.

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
- `whenNotScanned`: what happens when nothing, or not everything, was scanned (an error, a file over the size limit, more than 500 changed files, an unresolved merge conflict; with `requireAuthorization` also not authorized or a timeout). Unset, it equals `mode`. With `block`, such a commit stops. With `"warn"`, it goes through with a warning. It is never a silent pass: the output says `NOT scanned` and why.
- An invalid `pgard.config.json` is ignored as a whole and means `block`.

## Exit codes (`pgard precommit`)

| Code | Meaning                                                                                                                                                                                                                          |
| ---- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | Nothing blocks the commit (clean, warn mode, or nothing scanned with `whenNotScanned: warn`, which is said on screen).                                                                                                           |
| 1    | Findings in block mode (a crash of Node itself also exits 1; both block).                                                                                                                                                        |
| 2    | Invalid command, or `install` / `uninstall` refused.                                                                                                                                                                             |
| 3    | With `requireAuthorization`: not authorized (nothing scanned) and `whenNotScanned` blocks. Never in the default code-only mode, except a repository whose work tree Git redirects with `core.worktree`, which is refused with 3. |
| 4    | Other cases where not everything was scanned, and `whenNotScanned` blocks.                                                                                                                                                       |
| 5    | Internal error.                                                                                                                                                                                                                  |
| 130  | Cancelled.                                                                                                                                                                                                                       |

For exit 3 with `requireAuthorization`, the fix is the user's: they run `pgard login` in their own terminal.

## Steps

1. Run `pgard precommit` in the repository the user named, after the user has staged their changes (do not stage for them without asking). It reads the index and changes nothing.
2. Read the exit code and the output.
3. **Exit 1 (block):** list each finding by rule id, severity and `file:line`, with redacted evidence only. Suggest that the user removes the secret from the staged file, loads it from an environment variable, and rotates the credential if it was ever pushed or shared. They restage and commit.
4. **Exit 3 or 4, or `NOT scanned` lines:** say what was not scanned and why (for example a file over 1 MiB, more than 500 changed files, a merge conflict). Do not call the commit safe. Real fixes first: the user signs in with `pgard login` (for exit 3 with `requireAuthorization`), or splits the change. You may explain that `git commit --no-verify` and `"whenNotScanned": "warn"` exist and what they cost (the unscanned content is committed unchecked; a secret ends up in Git history), but do not propose or run them.
5. **Exit 0:** say that the staged changes had no new findings in what was scanned, and repeat any `NOT scanned` or "Not scanned by design" lines. If this is not a Git repository, or nothing is staged, say that nothing was checked. A secret hidden inside a skipped binary file is not found.
6. Install the hook only on the user's request; normally the user runs `pgard precommit install` themselves. A terminal is needed only when it would replace a hook PGARD did not write (the old one is kept as `pre-commit.pgard-backup`); it refuses an unsafe `core.hooksPath`. For a hook manager such as husky or the pre-commit framework, `pgard precommit snippet` prints the lines. `pgard precommit uninstall` removes the hook. A clean merge commit runs `pre-merge-commit`, which `install` does not write.

## Example

User: "My commit was rejected by pgard."

1. `pgard precommit` exits 1 and prints `PG-SECRET-002` (high) at `src/config.js:4`, evidence redacted.
2. Reply: "The hook blocked the commit (exit 1, `mode: block`). It found a credential (`PG-SECRET-002`, high) at `src/config.js:4`. I suggest you read it from an environment variable instead and rotate the credential if it was ever shared; rotating and cleaning history are yours to do. If you want me to edit the file, the value would enter my context, so I would not quote it in any answer, diff or commit message. I will not commit or use `--no-verify`; bypassing would commit the secret into history."

User: "Just fix everything and commit." Show each change first and wait for confirmation. If the hook blocks the commit, do not use `--no-verify`.
