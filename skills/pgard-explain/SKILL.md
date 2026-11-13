---
name: pgard-explain
description: Explain a PGARD scan result (findings, severity, confidence, evidence, exit codes, partial or not-tested areas) and suggest fixes. Use when the user shares or has a pgard result, JSON or text, and wants to understand it. Do not use to run new scans (use pgard-scan), to reveal secret values, or to apply fixes without confirmation.
---

# pgard-explain

Checked against pgard 0.3.0 (`README.md`). For rule details beyond this text, run `pgard rules list` (local, no network) or `pgard rules list --language <js|ts|react|vue|go|java|kotlin|python|php>`.

## Safety rules (always apply)

1. **Exit 3 (authorization did not pass):** nothing was scanned. Never relax it or suggest `--code-only` as a workaround. Offer a code-only scan only if the user asks for one, and say its result is "authorization not verified".
2. **Exit 4 or any area marked `partial` or `not_tested`:** report what was not checked. Never call the project safe or clean, and never read "no findings" as "secure". Detection is pattern-based and not complete.
3. **Never ask for, print, guess or reconstruct secret values.** Use only the redacted evidence. If the user pastes a real secret, do not repeat it; tell them to rotate it.
4. **Do not run `scan web`, `scan all`, or any scan of a target the user did not name.** Do not run `pgard login`, touch the keychain or use device codes; those are the user's steps.
5. **Suggest fixes; do not apply, commit or push them** without the user's confirmation. A pgard fix diff is a suggestion to review: pgard has not checked that it compiles or keeps behaviour.

## Prerequisites

`npm install -g pgard` (Node.js 22.23.4, 24.22.1 or 26.12.1 or a newer patch on the same line), then `pgard doctor` to check the setup.

## Reading the exit code

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

## Reading a finding

- **Rule id** (for example `PG-SECRET-001`: a new `.env` file; `PG-SECRET-002`: a credential). Look up a rule with `pgard rules list`.
- **Severity:** critical, high, medium, low, info (most to least urgent). `info` findings do not count in a pre-commit check.
- **Status:** `confirmed`, `suspected` or `informational`. Order of trust: confirmed, then suspected, then informational.
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
5. Suggest a fix per finding. For secrets: remove the value from the code, load it from the environment, and rotate the exposed credential, since Git history may still hold it. Ask before changing any file.

## Example

User: "pgard exited 4 with 2 findings, is it fine?"

Reply: "No, I cannot call it fine. Exit 4 means part of the scan did not run. Area `web` is `not_tested` (no web target was confirmed) and `history` is `partial` (stopped at its time budget), so those were not checked. The two findings are `PG-SECRET-002`, high, confirmed, in `config/db.js:12` (a credential, evidence redacted), and one low-confidence `; inferred` finding. Suggested fix for the first: move the credential to an environment variable and rotate it. Do you want me to make that edit?"
