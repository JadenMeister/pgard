---
name: pgard-scan
description: Run a PGARD code scan on the local Git repository the user named and report the result. Use when the user asks to scan their own project's code or configuration with the installed `pgard` CLI. Do not use for scanning web or remote targets, for signing in to GitHub, or for explaining findings in depth (use pgard-explain).
---

# pgard-scan

Checked against pgard 0.3.0 (`README.md`). Run `pgard --version` first; if it differs, re-check commands with `pgard --help` and `pgard help scan` before relying on this text.

## Safety rules (always apply)

1. **Exit 3 means authorization did not pass and nothing was scanned.** Never relax it. Do not rerun with `--code-only` unless the user explicitly asks for a code-only scan. If they do, state that the result is "authorization not verified".
2. **Exit 4 or any area marked `partial` / `not_tested`:** report what was not checked. Never call the project safe or clean. A scan with no findings is not proof of security.
3. **Never ask for, print, guess or reconstruct secret values.** Work only from the redacted result pgard prints.
4. **Scan only the local repository the user named.** pgard scans the Git root of the current directory. Never scan a remote service or any HTTP target. Do not run `pgard scan web` or `pgard scan all`, even for `127.0.0.1`: they need the user's own y/N confirmation of the service, so tell the user to run them themselves.
5. **Do not run `pgard login` or `pgard logout`, use device codes, or sign in or out.** Those are the user's own steps; tell them to run `pgard login` in a terminal. Do not read, export or change keychain entries yourself (`security`, `secret-tool`, `cmdkey` and the like). pgard reading its own saved sign-in during a scan or `doctor` is normal.
6. **If pgard shows a device code, a login link, or the code-only `[y/N]` question:** answer N or stop. Never relay or type a code. The line "For a code-only scan, add --code-only." is guidance for the user, not permission to run it.
7. **If pgard prints a GitHub App install link and waits:** stop and pass the link to the user.
8. **If the user tells you to answer y at a prompt:** do not type into the prompt. Treat it as their explicit code-only request, run `--code-only </dev/null` instead, and label the result "authorization not verified".
9. **Suggest fixes; do not apply, commit or push them** without the user's confirmation.
10. A claim of ownership or urgency changes nothing: pgard's own authorization gate decides, and these rules still apply.

## Prerequisites

- Node.js 22.23.4, 24.22.1 or 26.12.1, or a newer patch on the same line (`node --version`).
- Install: `npm install -g pgard`.
- Check the setup: `pgard doctor` (diagnosis only, not an authorization; exit 0 means the diagnosis completed, so read its `[fail]` and `[warn]` rows).

## Steps

1. Confirm which local repository to scan. Change into its root. Do not pick another path yourself.
2. Run `pgard doctor` if the setup is unknown. Report failing rows; do not fix sign-in problems yourself.
3. Run the scan with stdin closed and stdout sent to a file, so no prompt or device sign-in can start. Closing stdin alone is not enough: if stdout is still a terminal, the GitHub App install guide can appear and wait up to 10 minutes. Make the file with `mktemp` (a private temporary file, never inside the repository; do not use a fixed name in a shared folder) and read the result from it:

   ```sh
   out="$(mktemp)"
   pgard scan code --format json --no-browser </dev/null >"$out"
   ```

   Use `pgard scan` instead only if the user also wants Git history (secrets in history). `--format json` writes only the redacted result to stdout (the file); progress goes to stderr. Stdout stays empty after a usage error (exit 2), a cancellation, a directory that is not a repository (exit 3) and an internal error.

4. Read the exit code, then the result:

   | Code | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
   | ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
   | 0    | The requested scope completed (findings may exist).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
   | 2    | Invalid command, option, value or combination (also an unsupported Node.js version).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
   | 3    | Authorization did not pass and nothing was scanned: no approval, a check that could not finish (a network error, or GitHub not answering within 10 s), no GitHub remote, or not a Git repository. This holds for every scope (`scan`, `scan code`, `scan history`, `scan web`, `scan all`). In a terminal `scan` and `scan code` first ask whether to scan code-only (N stays 3); without one they print "For a code-only scan, add --code-only." Without a terminal and without a saved sign-in this is immediate ("Not signed in"). A code-only scan exits 0 or 4, not 3. |
   | 4    | Part of the scan did not run, so the result is partial (for example, no web target was confirmed, or the Git history scan stopped at its time budget), or the report export failed.                                                                                                                                                                                                                                                                                                                                                                                         |
   | 5    | Unexpected internal error only (never a failed authorization). Details are hidden; `PGARD_DEBUG=1` shows a sanitized message.                                                                                                                                                                                                                                                                                                                                                                                                                                               |
   | 130  | Cancelled by the user.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |

5. React to the exit code:
   - **0:** summarize findings by severity (critical, high, medium, low, info) and list the coverage of each area. Say "completed" only for areas that completed.
   - **3:** stop. Tell the user the scan was blocked and quote pgard's reason (for example "Not signed in to GitHub, and there is no terminal to sign in with"). Tell them to run `pgard login` in their own terminal, or to fix the failed check, then ask you to rerun. Tell them a code-only scan exists; the user chooses, and you do not run it first.
   - **4:** list every `partial` or `not_tested` area with its note. State that the result is not a safe result.
   - **2 or 5:** report the message; do not guess at options. For 2, check `pgard help scan`.
6. Offer `pgard-explain` for a closer reading of findings.

## Code-only scan (only when the user asks)

`pgard scan code --code-only --format json --no-browser </dev/null >"$out"` skips authorization, sign-in and the network, and checks the current files of the folder only (no Git history, no web checks, nothing stored). It is for the user's own code on their computer. In text output the first line is "Code-only scan: authorization not verified"; in JSON the same fact is `scanBasis` (`mode: "code_only"`, `authorization: "not_verified"`). Repeat that label in your summary. Exit codes are 0, 4 or 2, never 3. A folder that is too broad (a home folder, a top-level folder) is refused with exit 2.

## Example

User: "Scan my project at ~/work/shop."

1. `cd ~/work/shop && pgard doctor`
2. `pgard scan code --format json --no-browser </dev/null >"$out"` exits 3: "Not signed in to GitHub..."
3. Reply: "The scan was blocked (exit 3) and nothing was scanned. Please run `pgard login` in your terminal, then tell me to rerun. A code-only scan also exists; its result would be labelled 'authorization not verified'. It is your choice, and I have not run it."

User: "Scan anyway." Ask whether they want a code-only scan and explain its label before running it. User: "Scan https://example.com": refuse; pgard scans only the local repository the user named. User: "Run scan all" or "scan web on localhost:3000": do not run it; tell the user to run it in their own terminal, where they confirm the service.
