# PGARD Implementation, Commit, and Code Conventions

> **Note:** This document is the MVP planning record and a translation of the Korean original ([PGARD_DEVELOPMENT_CONVENTIONS_KO.md](PGARD_DEVELOPMENT_CONVENTIONS_KO.md)), which remains the authoritative record. The current behaviour is described in the [README](../README.md) ([한국어](../README.ko.md)); where they differ, the README is correct.

**Status:** Proposal for starting implementation. The product/CLI name `pgard`, local execution, permissions, and scan scope are already agreed. TypeScript/Node.js/React is still only the recommended stack, so if the final language changes, adjust only the syntax-related rules to the new language. This document is the working standard that the agents share before writing code in the actual Git repository.

## 1. Commit Granularity

One commit holds **one behavior change that can be explained, reviewed, and reverted independently**. Several commits may touch one file, and the code, required tests, and docs that complete one behavior go into the same commit. Do not split commits merely by file count or time spent.

- Do not mix the permission gate, scan rules, CLI screens, and report rendering in one commit. When changing a shared contract, include the contract change and all call-site updates together so the repository builds at every intermediate commit.
- A new security rule bundles its rule ID, detection condition, safe counter-example, result wording, and required verification into one unit. If the whole first SQL rule is large, split it by library or by input→execution flow.
- A fix commit must make the cause and the behavior change clear. Keep pure formatting separate from behavior changes. Leave a commit message that others can understand on every commit.
- Before committing, check the staged diff for target files, secrets, generated artifacts, and temporary reports. Do not put source code or tokens in commit messages, test output, or screenshots. Do not rewrite published commits on a shared branch without coordinating with the owner.

### Recommended implementation order and example commits

Below is an example in dependency order, and it **does not mandate the number of commits**. Split large items further, but never make a commit that allows actual scanning before the permission gate is verified.

| Order | Example commit                                                   | Result to verify independently                                                       |
| ----- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| 1     | `chore(repo): scaffold workspace and shared checks`              | App/package boundaries, shared type-check and formatting standards                   |
| 2     | `feat(findings): define scan scope and result contract`          | The `code/history/web` and `completed/partial/not_tested/not_selected` contract      |
| 3     | `feat(policy): reject scans without repository authorization`    | Analysis is blocked if any of owner approval, current access, or merged contribution is missing |
| 4     | `feat(cli): add project verification command`                    | Per-item pass and rejection reasons for `pgard project verify`                       |
| 5     | `feat(source-analysis): detect unsafe SQL interpolation`         | Positive and negative cases and suspected verdict for the first supported library    |
| 6     | `feat(git-history): find tracked secret exposure`                | Distinguishing current tracked state from past history, masking values               |
| 7     | `feat(http-local): restrict scans to confirmed loopback targets` | Port confirmation Y/N, redirect restrictions, time and URL count limits              |
| 8     | `feat(cli): add scoped and combined scans`                       | Per-scope results of `pgard scan`, `pgard scan code/history/web`, and `pgard scan all` |
| 9     | `feat(report): export redacted HTML and PDF`                     | Both formats generated from the same result schema, overwrite prevention             |
| 10    | `feat(local-web): show ephemeral scan dashboard`                 | `pgard dashboard` launcher, local API protection, state discarded on exit            |
| 11    | `docs(repo): add Korean and English usage guides`                | EN/KO READMEs, explanation of local processing, external communication, and limitations |

## 2. Commit Messages

The format is `type(scope): short summary starting with a verb`. Write the subject in English and aim for one line within 72 characters. If a body is needed, add after a blank line **why the change is made**, **behavior and security impact**, and **verification results**. If there is an issue number, link it in the body. Do not use `update`, `fix stuff`, or `misc`, whose subject alone leaves the reason for the change ambiguous.

| type       | Purpose                                                  |
| ---------- | -------------------------------------------------------- |
| `feat`     | Add a feature to be used by users or other packages      |
| `fix`      | Fix existing behavior or a security problem              |
| `refactor` | Structural improvement that does not change external behavior |
| `test`     | Only add or modify verification for existing behavior    |
| `docs`     | Documentation-only change                                |
| `chore`    | Repository management, configuration, generated-artifact cleanup |
| `build`    | Packaging/build system change                            |
| `ci`       | Automated check configuration change                     |
| `perf`     | Performance improvement backed by measurements           |

For `scope`, use the name of the package/app that actually owns the change: `repo`, `cli`, `local-web`, `scan-core`, `policy`, `github-auth`, `git-history`, `source-analysis`, `http-local`, `advisory`, `findings`, `report`. Even if a change spans several areas, pick the one primary responsibility boundary and describe the reason for the contract change and its impact in the body. Mark a breaking contract change with `feat(findings)!: ...` and `BREAKING CHANGE:` in the body. For security fixes, express the problem area as the scope, as in `fix(policy): ...`, instead of using a separate ambiguous type.

```text
fix(policy): reject unverified owner approval

An installation alone does not prove owner approval for this repository.
Keep the scan blocked when approval evidence is unavailable.

Verified: policy denial cases and CLI error mapping.
```

## 3. Branch and PR Boundaries

- Branch names are recommended to be `type/short-kebab-case`, such as `feat/cli-scoped-scans` and `fix/policy-owner-approval`. Keep each PR to a size in which one subsystem or one vertical feature can be reviewed. If multiple packages must change together, link the shared contract and the consumer changes in the PR description.
- Each PR states its purpose, scope, result screenshots or CLI output (sensitive values masked), test results, unsupported/partial scan scope, security impact, and how to revert. Review each PR awaiting review in a separate chat, resolve the problems found in that PR, and then report to the lead.
- A PR that changes the permission policy, result schema, or local web security boundary must be reviewed by the owner of the relevant package. Code ownership changes and cross-package interface changes are negotiated directly between the owners, with the lead notified. Merging to main is coordinated after the required reviews, CI, and protection rules pass.

## 4. Code Structure and Dependencies

- `apps/cli` and `apps/local-web` are separate executable apps. They do not import each other's source and use the shared contracts of `packages/scan-core`, `packages/findings`, `packages/report`, and so on. `pgard dashboard` is a launcher that explicitly starts the local web app.
- `scan-core` coordinates scans, and `policy` decides permissions. Neither the UI nor individual scanners may pass an approval failure on their own. Do not put file system access, GitHub tokens, or scan engine code in the browser bundle.
- A component used on only one screen stays in that feature's folder. If it is used on two or more screens, move it to `ui/components/` in the CLI or `client/components/` in the web app. The CLI and web rendering components are not shared; only the result types, aggregation, and masking functions are reused from the shared packages.
- Validate external input (CLI arguments, API requests, Git output, file contents) at the boundary. Treat project files as read-only, and do not run project scripts, builds, or dependency installs. Do not leave secrets in plain text in logs, exceptions, or reports.

## 5. Naming Rules (based on the recommended TypeScript stack)

| Target                  | Rule                                              | Example                                                      |
| ----------------------- | ------------------------------------------------- | ------------------------------------------------------------ |
| General files/folders   | `kebab-case`                                      | `verify-repository-access.ts`, `git-history/`                |
| React/TUI screens and components | `PascalCase.tsx`, or `.ts` depending on the TUI implementation | `FindingsPage.tsx`, `ChoiceList.ts`            |
| Variables/parameters    | Meaningful `camelCase`; collections in plural     | `targetPort`, `findings`, `approvedRepos`                    |
| Booleans                | Start with `is/has/can/should`                    | `isLoopback`, `hasOwnerApproval`, `canScan`                  |
| Functions               | `camelCase` verb + object expressing the action   | `verifyRepositoryAccess`, `scanGitHistory`, `redactEvidence` |
| Types/interfaces/classes | `PascalCase`; no `I` prefix                      | `ScanRequest`, `Finding`, `OwnerApprovalEvidence`            |
| Module-level constants  | `UPPER_SNAKE_CASE` only for fixed configuration values | `MAX_WEB_PAGES`, `DEFAULT_TIMEOUT_MS`                   |
| JSON/API fields         | `camelCase`, matching the existing shared schema  | `overallStatus`, `ruleId`, `webOrigin`                       |
| CLI commands/options    | Lowercase words and `kebab-case` flags            | `project verify`, `--target-port`                            |
| Environment variables   | `PGARD_` prefix + `UPPER_SNAKE_CASE`              | `PGARD_LOG_LEVEL`                                            |
| Scan rule IDs           | `PG-AREA-three-digit number`                      | `PG-SQL-001`, `PG-SECRET-001`                                |

Make broad names such as `data`, `result`, `item`, `handleThing`, `checkSecurity`, and `isSafe` more specific. For example, use `hasConfirmedOwnerApproval` instead of `isSafe`, and `verifyRepositoryAccess` instead of `checkSecurity`. If a function has side effects that write to files, the network, or reports, show verbs such as `read`, `fetch`, `write`, and `save` in its name. For pure computation such as parsing, normalization, and aggregation, use `parse`, `normalize`, and `summarize`.

## 6. Writing and Verification Standards

- If TypeScript is finally chosen, turn on `strict` mode and declare the input and output types of public functions explicitly. Accept external data as `unknown` and then validate it. Avoid `any` and arbitrary non-null assertions that skip boundary validation. Make errors carry distinguishable codes and causes instead of relying on string comparison.
- Define `ScanRequest`, `ScanResult`, `Finding`, and `Coverage` once in the shared package. Distinguish the requested scope from the scope that could not be run. `not_selected` means the user did not select it, `not_tested` means it was selected but could not be run, and `partial` means only part of it was run.
- For security rules, verify both a risky case and a safe counter-example. For the permission gate, verify that it rejects each of: no owner approval, no access permission, no contribution evidence, an ambiguous remote, and a forged author email. For local HTTP, verify that redirects outside loopback are blocked.
- For each change, run the relevant type check, lint, and meaningful tests, and record the results in the PR. For security/permission/data-masking changes, failure-case verification is mandatory. Do not write formalistic tests that merely mirror the implementation for simple documentation or formatting changes.
- When the scan scope, rules, or command behavior changes, update the Korean and English READMEs and the CLI help together. Do not promise users `finds all vulnerabilities` or `a fully non-mutating HTTP scan`.

## 7. Completion Report Format for Implementing Agents

Each owner reports to the lead, for the boundary they own, **what was changed**, **how it was split into commits**, **verification commands and results**, **remaining limitations and blockers**, and **contract changes needed from other owners**. Before changing scope or file ownership, negotiate directly with the counterpart owner and notify the lead. The lead gathers the independent review results per PR and checks the required verification status before merging to main.

## 8. Issues, Board and Review Workflow (current, post-MVP)

This section describes the rules actually used after the MVP. Where it differs from the planning record above, this section is correct.

### Issues

- Every piece of work (feature, bug, limitation, docs, chore) starts as a GitHub issue. Do not open a PR without one.
- A feature issue states its **goal**, its **scope** (what this issue does and does not do) and, where relevant, its **security and policy conditions**.
- A bug issue body uses these sections in order: **Summary / Found in / Severity / Failure scenario / Expected / Fix / Verification**.
- Labels:
  - exactly one `type:feature|bug|security|limitation|docs|chore`
  - one or more `area:<package>`: `area:findings`, `area:policy`, `area:scan-core`, `area:git-history`, `area:github-auth`, `area:source-analysis`, `area:http-local`, `area:report`, `area:cli`, `area:local-web`, `area:repo`
  - one `priority:p1|p2|p3`
  - status labels only when needed: `status:deferred` for postponed work and `status:needs-decision` for work waiting on a decision.
- Review findings that are not fixed in the PR become follow-up issues. Small ones may be grouped into one issue.

### Board

- Every issue goes on the GitHub Project board, with the status **Todo / In Progress / Done**.
- Status rules:
  - closed issues and merged PRs: **Done**
  - issues with an open PR or active work: **In Progress**
  - everything else: **Todo**
- PR bodies say `Closes #N`, so the issue closes when the PR is merged.

### Review and merge

- Every PR is reviewed by an **independent reviewer** who is not the implementer. The reviewer checks the code, the issue and CI directly rather than the implementer's conclusions, and verifies with their own mutation experiments and real runs where useful.
- Findings are classified by severity.
  - **blocker / major** block the merge. They are fixed in the same PR and checked again. Examples: bypassing a security or authorization gate, missing results or a false "safe", exposing secrets, wrong standards or licence statements, CI failures.
  - **minor / nit** do not block the merge. Fold them into the same PR where practical; otherwise leave a follow-up issue.
- main is protected. A PR must pass the required CI check `check`. A branch behind main is updated with the latest main first.
- Merge with a merge commit (`gh pr merge --merge`). Squash merges are not used.
- A change that relaxes the authorization policy is not merged without an explicit decision by the maintainer, whatever the review says.

### Commit and PR attribution

- Commit messages follow section 2. Commits written by an AI name the model in a `Co-Authored-By:` line.
- PR bodies written by an AI end with a line naming the tool that generated them.
