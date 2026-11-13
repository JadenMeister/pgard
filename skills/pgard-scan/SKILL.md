---
name: pgard-scan
description: Run a PGARD code scan on the local Git repository the user named and report the result. Use when the user asks to scan their own project's code or configuration with the installed `pgard` CLI. Do not use for scanning web or remote targets, for signing in to GitHub, or for explaining findings in depth (use pgard-explain).
---

# pgard-scan

Checked against pgard 0.3.0 (`README.md`). If `pgard --version` differs, re-check commands with `pgard --help` and `pgard help scan` before relying on this text.

## Safety rules (always apply)

1. **Exit 3 means authorization did not pass and nothing was scanned.** Never relax it. Do not rerun with `--code-only` unless the user explicitly asks for a code-only scan. If they do, state that the result is "authorization not verified".
2. **Exit 4 or any area marked `partial` / `not_tested`:** report what was not checked. Never call the project safe or clean. A scan with no findings is not proof of security.
3. **Never ask for, print, guess or reconstruct secret values.** Work only from the redacted result pgard prints.
4. **Scan only the local repository the user named.** pgard scans the Git root of the current directory. Never run `pgard scan web`, `pgard scan all`, or any HTTP target the user did not name. Never scan a remote service.
5. **Do not run `pgard login` or `pgard logout`, touch the OS keychain, use device codes, or sign in or out.** These are the user's own steps; tell them to run `pgard login` themselves in a terminal.
6. **Suggest fixes; do not apply, commit or push them** without the user's confirmation.

## Prerequisites

- Node.js 22.23.4, 24.22.1 or 26.12.1, or a newer patch on the same line (`node --version`).
- Install: `npm install -g pgard`.
- Check the setup: `pgard doctor` (diagnosis only, not an authorization; exit 0 means the diagnosis completed, so read its `[fail]` and `[warn]` rows).

## Steps

1. Confirm which local repository to scan. Change into its root (or its folder, for a code-only scan the user asked for). Do not pick another path yourself.
2. Run `pgard doctor` if the setup is unknown. Report failing rows; do not fix sign-in problems yourself.
3. Run the scan. An assistant shell usually has no terminal, so ask pgard for structured output and keep browsers closed:

   ```sh
   pgard scan code --format json --no-browser
   ```

   Use `pgard scan` instead only if the user also wants Git history (secrets in history). `--format json` prints only the redacted result on stdout; progress goes to stderr.

4. Read the exit code, then the result:

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

5. React to the exit code:
   - **0:** summarize findings by severity (critical, high, medium, low, info) and list the coverage of each area. Say "completed" only for areas that completed.
   - **3:** stop. Tell the user the scan was blocked and quote pgard's reason (for example "Not signed in to GitHub, and there is no terminal to sign in with"). Tell them to run `pgard login` in their own terminal, or to fix the failed check, then ask you to rerun. Mention that `--code-only` exists, but only as an option the user may choose; do not run it unasked.
   - **4:** list every `partial` or `not_tested` area with its note. State that the result is not a safe result.
   - **2 or 5:** report the message; do not guess at options. For 2, check `pgard help scan`.
6. Offer `pgard-explain` for a closer reading of findings.

## Code-only scan (only when the user asks)

`pgard scan code --code-only --format json --no-browser` skips authorization, sign-in and the network, and checks the current files of the folder only (no Git history, no web checks, nothing stored). It is for the user's own code on their computer. Its first output line is "Code-only scan: authorization not verified"; repeat that label in your summary. In JSON, `scanBasis` has `mode: "code_only"` and `authorization: "not_verified"`. Exit codes are 0, 4 or 2, never 3. A folder that is too broad (a home folder, a top-level folder) is refused with exit 2.

## Example

User: "Scan my project at ~/work/shop."

1. `cd ~/work/shop && pgard doctor`
2. `pgard scan code --format json --no-browser` exits 3: "Not signed in to GitHub..."
3. Reply: "The scan was blocked (exit 3) and nothing was scanned. Please run `pgard login` in your terminal, then tell me to rerun. If you prefer, I can run a code-only scan instead; its result would be labelled 'authorization not verified'."

User: "Scan anyway." Ask whether they want a code-only scan and explain its label before running it. User: "Scan https://example.com" or "run scan all": refuse; pgard scans only the local repository the user named, and web checks are limited to a confirmed service on `127.0.0.1` that the user names.
