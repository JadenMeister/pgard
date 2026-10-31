# Contributing to PGARD

Thank you for helping. PGARD is a local security scanner, so changes are reviewed with extra care for authorization, privacy and honest results.

By taking part you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md). To report a vulnerability in PGARD itself, read [SECURITY.md](SECURITY.md) and do not use a public issue.

## Start with an issue

Every change starts as a GitHub issue, and a pull request should say `Closes #N`. For a bug, describe what happened, what you expected and how to reproduce it. For a feature, describe the goal and what is out of scope. Please check the [open issues](https://github.com/JadenMeister/pgard/issues) first. The full workflow (labels, review, merge) is in [`docs/PGARD_DEVELOPMENT_CONVENTIONS_EN.md`](docs/PGARD_DEVELOPMENT_CONVENTIONS_EN.md).

## Development setup

You need Node.js 22.23.4, 24.22.1 or 26.12.1 (or a newer patch on the same line) and Git. This is an npm workspaces monorepo written in TypeScript.

```sh
git clone https://github.com/JadenMeister/pgard.git
cd pgard
npm ci
npm run build          # TypeScript packages and the dashboard UI
npm link -w @pgard/cli # optional: puts `pgard` on your PATH
```

Without `npm link`, run `node apps/cli/dist/bin/pgard.js <command>`. The [Development section of the README](README.md#development) lists the packages. Never run a scan against a repository you are not authorized to scan, and never commit real secrets, tokens or private repository data in tests or fixtures.

## Checks that must pass

CI runs these on pull requests and on `main`. Please run them locally before you push:

```sh
npm run build
npm run typecheck
npm run format:check   # `npm run format` fixes formatting
npm test
npm run corpus:check
```

`npm run check` runs typecheck, format check and tests together. When you change the packaging, also run `npm run pack:pgard` and `npm run smoke:pack`.

**Timing in tests.** Do not compare a duration with a bare number. Import `TIME_FACTOR` (or `scaled`, `bestTimeOf`) from [`tests/support/timing.ts`](tests/support/timing.ts) and scale the budget with it: the factor is 1 locally, 3 when `CI` is set, and 3 times more on Windows. Set `PGARD_TEST_TIME_FACTOR` to a positive number to override it, for example `PGARD_TEST_TIME_FACTOR=5 npm test` on a busy machine (invalid values are ignored). For a "stays linear" test, time size n against 4n and assert a ratio, and keep the absolute ceiling generous: it is only a hang guard. The vitest test and hook timeouts scale with the same factor.

## Commits and pull requests

- Use `type(scope): short summary starting with a verb`, for example `fix(policy): reject unverified owner approval`. The scope is the package or app that owns the change (`cli`, `local-web`, `scan-core`, `policy`, `github-auth`, `git-history`, `source-analysis`, `http-local`, `findings`, `report`, `repo`). Keep the subject within 72 characters, and explain why in the body when it is not obvious.
- Keep one logical change per commit and per pull request.
- Say how you verified the change. Add or update tests for behavior you change.
- Do not relax the authorization gate or add a way to skip it. Such a change is not merged without an explicit decision by the maintainer.
- Do not add trackers, telemetry or new network destinations. What leaves the machine is documented in the README's privacy section, and any change to it must update that section.
- Keep README.md and README.ko.md in step with behavior changes, and keep claims honest: say what is not covered.

## Rule changes and the accuracy corpus

Every rule is measured against the labelled corpus in [`tests/corpus/`](tests/corpus/). When you add or change a rule:

- Add vulnerable samples under `tests/corpus/<RULE-ID>/positive/` and safe samples under `tests/corpus/<RULE-ID>/negative/`. Include hard cases, not only easy ones. History rules are described in `tests/corpus/history-cases.mjs` and web rules in `tests/corpus/web-cases.mjs`.
- A negative sample that is only safe through something PGARD infers (a guard, an allowlist, a constant) must carry `expect=low` in its header: the rule must still report it, capped at low confidence. Guards lower confidence, they never hide a finding.
- Every miss or false positive you leave in the corpus must be declared with a reason (`known=`). Do not delete hard cases to improve a score.
- Run `npm run build && npm run corpus` to rewrite `tests/corpus/RESULTS.md`, and commit it. `npm run corpus:check` fails when a rule falls below its recorded threshold or when `RESULTS.md` is out of date.
- Add the rule to the rule catalog with its severity, languages, and OWASP, CWE and CERT mapping, and keep the README's analyzer tables in step.

## Pull request review

Every pull request gets an independent review and must pass the required `check` job. Findings that block a merge (a bypassed gate, a false "safe", exposed secrets, wrong standards or license statements, CI failures) are fixed in the same pull request. Merges use a merge commit.

## License

By contributing you agree that your contribution is released under the [MIT License](LICENSE).
