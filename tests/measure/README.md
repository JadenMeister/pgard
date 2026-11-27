# Real-repository recall measurement

Measures how many known, published vulnerabilities in real open-source projects PGARD's code-only scan points at. It is a measurement, not a gate: there are no thresholds and it is not wired into CI (it needs the network and is slow).

## Data

`cases.json`: 113 verified cases (GHSA id, public GitHub repo, fix commit, its vulnerable parent commit, CWEs, and the old-file lines of the vulnerable code at the vulnerable commit). Extra fields: `doubtful` (set from the committed `doubtful.json`, one reason per id: the expected lines or CWE are less certain) and `inScope` (a CWE that PGARD has a rule for, see `cwe-families.mjs`). The dataset test checks both against the files and checks shas, repo names and line ranges.

## Ethics

- Public repositories only, fetched anonymously (no token, no sign-in, no GitHub App).
- Everything stays local. Repository code is never executed: git only reads objects (no hooks, no filters, empty config) and PGARD only parses files.
- Results hold rule ids and file/line locations, never evidence text or secret values.
- If a run ever surfaces a real, still-unfixed vulnerability that is not in the dataset, report it privately to the maintainers before any publication.

## Run

```
npm run build
npm run measure -- --lang go --limit 5            # a few cases
npm run measure -- --id GHSA-xxxx-xxxx-xxxx
npm run measure -- --jobs 4 --fix-check           # all cases, also scan the fixed commit
```

Options: `--lang`, `--id` (repeatable), `--limit`, `--jobs` (default 2), `--fix-check`, `--out <dir>` (default `tests/measure/out/`, git-ignored; gets `results.json` and `RESULTS-REAL.md`), `--cache <dir>` (default `~/.cache/pgard-measure`, bare repos holding only the fetched commits), `--write-results` (write `tests/measure/RESULTS-REAL.md`; refused together with `--lang`, `--id` or `--limit`, so only a full run can replace the placeholder).

Each case: shallow-fetch only the vulnerable commit (and the fix commit with `--fix-check`), check it out into a temporary folder, and scan it with `runCodeOnlyScan` (same as `pgard scan --code-only`).

## Hit rule

A finding matches a case when its rule id is one of the rules mapped to one of the case's CWEs (`cwe-families.mjs`, built from the rules' own CWE standards; a test enforces it; CWE-330 and CWE-338 are assumed to be PG-CRYPTO-003, which detects predictable random values but does not list them).

- `hit`: a matching finding in an expected file within +-5 lines of any expected range.
- `loose`: a matching finding in an expected file, but not near the lines.
- `miss`: neither, and the relevant analyzers completed.
- `not-tested`: nothing found, but a language area (`source:<language>`) or an area carrying a rule of the family was `not_tested`: the silence proves nothing, so it is never a miss.
- `unsupported-language`: nothing found and no analyzer that carries a rule of the family ran on the repository (decided from the scan's own coverage, not from file extensions, so JSP, Thymeleaf and Kotlin script files are judged by the scan).
- `no-rule`: PGARD has no rule for the CWE (authentication 287/306, configuration 16/1188, 326, 611, ...). Reported separately, not fetched, never a miss of an existing rule; `inScope` is false.
- `fetch-error` / `scan-error`: the case could not be measured. A scan that hits its 10-minute limit is a `scan-error`, not partial. `fetch-error` is also used when the fetched tree lacks every expected file.

Recorded per case: status, matched rule ids, `partial` (any coverage area partial or not_tested, `not_selected` and the `deps:*` areas excluded, since dependency matching is off here; area ids in `partialAreas`; shown as a separate column, a hit can be in a partial scan), findings count, same-family and any-finding counts in the expected files, wall time, process RSS after the scan (with `--jobs` above 1 it covers all running cases). With `--fix-check` (hits only): `fixGone` is true when the fixed commit has no finding of the matched rules near the expected old-file lines (a fix that moves code can read as gone); `null` when the expected file was removed at the fix. Recall is over the cases that have a rule; not-tested, errors and unsupported languages stay in the denominator. Per-family rows can overlap (a case with CWEs of two families counts in both).

## Caveats

- CWE skew: the dataset is dominated by XSS, SQL injection and path traversal; small groups (n shown in every table) are noise, not rates.
- Doubtful cases have approximate lines; the aggregate shows `all`, `non-doubtful` and `in-scope` separately.
- A "hit" shows PGARD flagged the right place, not that the finding was the exact flaw; "loose" is a weaker signal.
- Kotlin and the other tree-sitter languages (Java, Python, PHP) have fewer rules than JS/TS/Go, so lower recall there is expected.
- Dependency findings are off (no advisory data is given), so only source and working-tree secret rules are measured.
- No baseline is committed until a full run was done: see `RESULTS-REAL.md`.
