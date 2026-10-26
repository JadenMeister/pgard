# Scan result schema and versioning

The scan result (`ScanResult` in `packages/findings/src/contract.ts`) carries a `schemaVersion` in `major.minor` form. The current version is `1.0`. This document says when that version changes and what a reader must do with a version it did not write.

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
| Same (`1.0`)                  | Accepted.                                                                                                                           |
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

## Changing the version

The version constant `SCHEMA_VERSION` is bumped in the same pull request that changes the shape, together with a note here and tests for the new compatibility case. The reader's accepted major is derived from that constant.
