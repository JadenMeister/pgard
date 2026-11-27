# Real-repository recall measurement

Measures how many known, published vulnerabilities in real open-source projects PGARD's code-only scan points at. It is a measurement, not a gate: there are no thresholds and it is not wired into CI (it needs the network and is slow).

## Data

`cases.json`: 113 verified cases (GHSA id, public GitHub repo, fix commit, its vulnerable parent commit, CWEs, and the old-file lines of the vulnerable code at the vulnerable commit). Extra fields: `doubtful` (the note says the lines are estimated, added-lines-only, context, loose, ... so the expected lines are less certain) and `inScope` (a CWE that PGARD has a rule family for, see `cwe-families.mjs`).

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

Options: `--lang`, `--id` (repeatable), `--limit`, `--jobs` (default 2), `--fix-check`, `--out <dir>` (default `tests/measure/out/`, git-ignored; gets `results.json` and `RESULTS-REAL.md`), `--cache <dir>` (default `~/.cache/pgard-measure`, bare repos holding only the fetched commits), `--write-results` (write `tests/measure/RESULTS-REAL.md`, for a full run only).

Each case: shallow-fetch only the vulnerable commit (and the fix commit with `--fix-check`), check it out into a temporary folder, and scan it with `runCodeOnlyScan` (same as `pgard scan --code-only`).

## Hit rule

A finding matches a case when its rule id is in the rule family of one of the case's CWEs (`cwe-families.mjs`).

- `hit`: a matching finding in an expected file within +-5 lines of any expected range.
- `loose`: a matching finding in an expected file, but not near the lines.
- `miss`: neither. Also the status when the CWE has no rule family.
- `unsupported-language`: no expected file has a source extension PGARD analyzes. `fetch-error` / `scan-error`: the case could not be measured (`fetch-error` is also used when the fetched tree lacks every expected file).

Recorded per case: status, matched rule ids, `partial` (a code area was partial; area ids in `partialAreas`), findings count, same-family and any-finding counts in the expected files, wall time, process RSS after the scan (with `--jobs` above 1 it covers all running cases). With `--fix-check`: `fixGone` is true when the fixed commit has fewer same-family findings in the expected files. Scans that run out of time are reported as partial, never as clean.

## Caveats

- CWE skew: the dataset is dominated by XSS, SQL injection and path traversal; small groups (n shown in every table) are noise, not rates.
- Doubtful cases have approximate lines; the aggregate shows `all`, `non-doubtful` and `in-scope` separately.
- A "hit" shows PGARD flagged the right place, not that the finding was the exact flaw; "loose" is a weaker signal.
- Kotlin and the other tree-sitter languages (Java, Python, PHP) have fewer rules than JS/TS/Go, so lower recall there is expected. Cases whose files are not analyzed at all are `unsupported-language`.
- CWEs outside the map (for example 338, 611, 601) have no rule family and can only be `miss`; they count in `all` only.
- Dependency findings are off (no advisory data is given), so only source and working-tree secret rules are measured.
- No baseline is committed until a full run was done: see `RESULTS-REAL.md`.
