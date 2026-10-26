# Scan result schema and versioning

> [한국어](RESULT_SCHEMA.ko.md) translation available. This English file is the reference; the translation follows it.

The scan result (`ScanResult` in `packages/findings/src/contract.ts`) carries a `schemaVersion` in `major.minor` form. The current version is `1.1`. This document says when that version changes and what a reader must do with a version it did not write.

## Version rules

**Minor** (`1.0` to `1.1`): additive and optional only.

- A new optional field, or a new field that older readers can ignore.
- A new value in an open-ended string field (for example a new rule id).

**Major** (`1.x` to `2.0`): anything else.

- A field removed, renamed or retyped.
- A change in the meaning of an existing field.
- A new value in a closed enum (severity, status, category, scope, and so on), because an old reader cannot interpret it.
- A change in how `Finding.id` is derived (see below).

Fields marked deprecated (such as `advisoryDb`) keep their shape until the next major version.

## Reading rules

Readers ignore fields they do not know. Anything that reads a result back (stored results, CI tools, report and SARIF converters) goes through `readScanResult` from `@pgard/findings`. It validates the shape strictly, never throws, and returns either the typed result or a typed error.

| Input version                 | Behaviour                                                                                                                           |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| Same (`1.1`)                  | Accepted.                                                                                                                           |
| Older minor of the same major | Accepted. Fields added later are absent; the shape is still valid.                                                                  |
| Newer minor of the same major | Accepted. Unknown fields are ignored (the reader drops them). `sourceVersion` reports the version the file carried.                 |
| Other major                   | Refused with `version_unsupported_major` and a message naming the version. The reader never tries to convert or guess.              |
| Missing or malformed          | Refused with `version_missing` or `version_malformed`. A valid version is exactly two dot-separated integers without leading zeros. |

The version grammar is `major.minor`, each part a non-negative integer of at most 6 digits and without leading zeros.

A version that is accepted is still checked against the full shape. A wrong enum value, a missing required field, a hole in an array, a duplicate `Finding.id`, a line number below 1 or an oversized array is refused with `invalid_shape` or `too_large`, whatever the version says. The reader reads own data properties only (it never runs getters), and caps array sizes, string lengths and the total number of array entries (`READ_LIMITS`), so a hostile file cannot make it do unbounded work after parsing. Callers must cap the file size before `JSON.parse`; the reader cannot do that for them.

Strings are length-capped but not sanitized. Evidence, titles and notes can contain any characters, and escaping them for HTML, terminals or SARIF is the job of whatever renders them.

**Write-back.** The reader returns the fields it knows and drops the rest. When `sourceVersion` is newer than `SCHEMA_VERSION`, never write the reader's output back over the source file: that would silently delete the newer fields. Save a copy under another name, or refuse.

## Which outputs carry the version

- Any JSON output of a scan, including the planned CLI JSON output (`schemaVersion` at the top level).
- Stored results (the same object, written as is).
- Reports built from a result (HTML and PDF). They print the normalized `schemaVersion` of the reader (the version this PGARD implements), not necessarily the version the source file carried.

## Finding.id is a fingerprint

`Finding.id` is a stable fingerprint of rule, location and cause. Stored results are compared with later scans by this id, so it is part of the contract even though its type is only `string`. Changing how it is derived makes ids from older results stop matching, so such a change is a **major** version change. Its type or the rule that it never contains secret values cannot change within a major version either.

## Version history

**1.1** (additive; a minor bump). Two optional top-level fields. A `1.0` result has neither, and a reader treats a missing field as "not recorded", never as "nothing ran" or "nothing checked".

- `ruleStats` (`RuleStat[]`): one entry per rule and coverage area where the rule ran (`completed` or `partial`). `ruleId`, `area` (a `Coverage.area`), `scope`, `status` (the area's status), `findings` (findings the rule reported in that area, counted before findings of several scopes are merged) and `targets`: a list of `{ unit, examined, reason }`. `unit` is an open string (`files`, `commits`, `blobs`, `pages`, `responses`, `unknown`; a new unit is not a schema change). `examined` is a count the analyzer measured, or `null` when it cannot be measured, and then `reason` says why (`reason` is `null` otherwise). An analyzer that reports nothing gets `{ unit: "unknown", examined: null, reason }`, never a guess. The same finding can count in two entries only for `source:react` and `source:heuristics`, which look at files that a language area also covers.
- `standardsCoverage` (`{ owasp, cweTop25 }`): one `StandardCoverageEntry` per OWASP Top 10 2025 category (A01 to A10, in order) and per CWE Top 25 2025 entry (rank order): `id`, `title`, `rank` (`null` for OWASP), `state`, `ruleIds` (rules that ran and contribute), `mappedRuleIds` (every rule of this PGARD version that maps to the entry) and a short English `reason`. `state` is `checked`, `partial` or `not_checked`; it is a closed enum, so a new state would be a major change. It is derived by `computeStandardsCoverage` from the rule mappings and from the scan's own coverage and `ruleStats`: `checked` needs a mapped rule that ran, every contributing area `completed`, and every language present covered by a completed mapped rule (history and web rules are not language-bound); `partial` is some mapped rule that ran with a `partial` area or an uncovered language; `not_checked` is no mapped rule ran, or none exists (reason `no rules`). "Checked" says a rule ran to completion, not that the weakness is absent. Advisories (OSV) are not rules of a scan and never count.

A blocked or failed scan writes `ruleStats: []` and a `standardsCoverage` in which every entry is `not_checked`.

**1.0**: the original shape.

## Changing the version

The version constant `SCHEMA_VERSION` is bumped in the same pull request that changes the shape, together with a note here and tests for the new compatibility case. The reader's accepted major is derived from that constant.
