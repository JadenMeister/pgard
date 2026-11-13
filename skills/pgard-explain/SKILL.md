---
name: pgard-explain
description: Explain a PGARD scan result (findings, severity, confidence, evidence, exit codes, partial or not-tested areas) and suggest fixes. Use when the user shares or has a pgard result, JSON or text, and wants to understand it. Do not use to run new scans (use pgard-scan), to reveal secret values, or to apply fixes without confirmation.
---

# pgard-explain

Checked against pgard 0.3.0 (`README.md`). Run `pgard --version` first; if it differs, re-check with `pgard --help`. For rule details beyond this text, run `pgard rules list` (local, no network) or `pgard rules list --language <js|ts|react|vue|go|java|kotlin|python|php>`.

## Safety rules (always apply)

1. **Exit 3 (authorization did not pass):** nothing was scanned. Never relax it or suggest `--code-only` as a workaround. Tell the user a code-only scan exists; the user chooses, and you do not run it first. Its result is "authorization not verified".
2. **Exit 4 or any area marked `partial` or `not_tested`:** report what was not checked. Never call the project safe or clean, and never read "no findings" as "secure". Detection is pattern-based and not complete.
3. **Never ask for, print, guess or reconstruct secret values.** Use only the redacted evidence. If the user pastes a real secret, do not repeat it; tell them to rotate it.
4. **Do not run `scan web` or `scan all`, even for `127.0.0.1`:** they need the user's own y/N confirmation of the service, so tell the user to run them. Never scan a remote service or a target the user did not name.
5. **Do not run `pgard login` or `pgard logout`, or use device codes.** Those are the user's steps. Do not read, export or change keychain entries yourself (`security`, `secret-tool`, `cmdkey` and the like). pgard reading its own saved sign-in during a scan or `doctor` is normal.
6. **Suggest fixes; do not apply, commit or push them** without the user's confirmation. A pgard fix diff is a suggestion to review: pgard has not checked that it compiles or keeps behaviour.
7. **Secrets:** editing the flagged line puts the value into your context. Suggest that the user makes the change. If you make it, never quote the value in an answer, a diff or a commit message. Rotating the key and cleaning Git history are always the user's job.

## Prerequisites

`npm install -g pgard` (Node.js 22.23.4, 24.22.1 or 26.12.1 or a newer patch on the same line), then `pgard doctor` to check the setup.

## Reading the exit code

| Code | Meaning                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | The requested scope completed (findings may exist). For `doctor`: the diagnosis completed.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| 1    | `pgard precommit` in block mode: the staged changes have findings, so the commit is stopped. Only this command returns 1.                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| 2    | Invalid command, option, value or combination (also `pgard login` without a terminal; a refused `pgard precommit install` or `uninstall`; an unsupported Node.js version).                                                                                                                                                                                                                                                                                                                                                                                                  |
| 3    | Authorization did not pass and nothing was scanned: no approval, a check that could not finish (a network error, or GitHub not answering within 10 s), no GitHub remote, or not a Git repository. This holds for every scope (`scan`, `scan code`, `scan history`, `scan web`, `scan all`). In a terminal `scan` and `scan code` first ask whether to scan code-only (N stays 3); without one they print "For a code-only scan, add --code-only." Without a terminal and without a saved sign-in this is immediate ("Not signed in"). A code-only scan exits 0 or 4, not 3. |
| 4    | Part of the scan did not run, so the result is partial (for example, no web target was confirmed, or the Git history scan stopped at its time budget), or the report export failed.                                                                                                                                                                                                                                                                                                                                                                                         |
| 5    | Unexpected internal error only (never a failed authorization). Details are hidden; `PGARD_DEBUG=1` shows a sanitized message.                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| 130  | Cancelled by the user.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |

## Reading a finding

- **Rule id** (for example `PG-SECRET-001`: an environment file committed to Git; `PG-SECRET-002`: a credential). Look up a rule with `pgard rules list`.
- **Severity:** critical, high, medium, low, info (most to least urgent). `info` findings do not count in a pre-commit check.
- **Status:** `confirmed`, `suspected` or `informational`, ordered from most to least certain.
- **Confidence:** how sure pgard is. A value that is only inferred to be safe stays in the result at low confidence (medium severity at most), with evidence ending in `; inferred`. Guards lower confidence; they never hide a finding. Dependency findings are never high confidence: they say a version is inside an advisory's affected range, not that the code is reachable or exploitable.
- **Evidence:** redacted. A secret value is replaced by its kind. Never try to recover it.
- **Test, fixture or vendored code:** findings there are listed apart and their confidence is capped at low. Critical, high and secret findings there are still listed.
- **Location:** `file:line` or URL. Grouped findings (same rule and cause) show the first locations. `--all-findings` lists every location with evidence, and `--fixes` adds suggested-fix diffs where a rule has one. These are options to a scan the user asked for, not reasons to rescan on your own.

## Reading coverage and partial states

Each area has one status:

| Status         | Meaning                                                 |
| -------------- | ------------------------------------------------------- |
| `completed`    | The area ran to the end. Findings may or may not exist. |
| `partial`      | Only part of the area ran. A note says what is missing. |
| `not_tested`   | You selected the area, but it could not run.            |
| `not_selected` | You did not request the area.                           |

Report every `partial` and `not_tested` area with its note (the items that "could not be checked"), and say that `not_selected` areas were not requested. Without downloaded advisory data (`pgard advisories update`, which the user runs), the dependency areas are `not_tested`. pgard prints "Not a safe result" whenever the scan is incomplete. Standards-map states (`rules ran`, `rules partial`, `not run`, `no rules`) never mean "safe" or "covered".

## Steps

1. Get the result from the user (pasted, or a JSON file they name). Do not rerun a scan to get it unless they ask; if they do, use pgard-scan.
2. State the exit code and its meaning from the table. If the result is code-only (`scanBasis.mode` is `code_only`), say "authorization not verified".
3. Summarize: counts by severity; then the top findings by rule id, severity, confidence and location.
4. State what was not checked.
5. Suggest a fix per finding. For secrets: the user removes the value from the code, loads it from the environment, rotates the exposed credential and decides about Git history, which may still hold it. Ask before changing any file.

## Example

User: "pgard exited 4 with 2 findings, is it fine?"

Reply: "No, I cannot call it fine. Exit 4 means part of the scan did not run. Area `web` is `not_tested` (no web target was confirmed) and `history` is `partial` (stopped at its time budget), so those were not checked. The two findings are `PG-SECRET-002`, high, confirmed, in `config/db.js:12` (a credential, evidence redacted), and one low-confidence `; inferred` finding. For the first, I suggest you move the credential to an environment variable and rotate it; rotating and cleaning history are yours to do. If you want me to edit the file, note that doing so puts the value in my context, so I will not quote it anywhere. Tell me if you want that."

User: "Just fix everything and commit." Show each proposed change first, ask for confirmation, and do not commit without it. If a hook blocks the commit, do not use `--no-verify`.
