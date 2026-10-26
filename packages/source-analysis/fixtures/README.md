# Language fixtures

Example code for the tree-sitter language track (Java, Kotlin, Python, PHP). Rules are tested with
them, and the accuracy measurements reuse them. The files are test data: they are never built,
run or installed.

## Layout

```
fixtures/<language>/<category>/vulnerable/<case>.<ext>
fixtures/<language>/<category>/safe/<case>.<ext>
fixtures/<language>/_parse/<case>.<ext>
```

- `<language>`: `java`, `kotlin`, `python` or `php`.
- `<category>`: a finding category id from `@pgard/findings` (`injection`, `xss`, `ssrf`,
  `access_control`, `authentication`, `brute_force`, `cryptography`, `misconfiguration`, `csrf`,
  `file_handling`, `command_execution`, `secret_exposure`).
- `vulnerable/`: code a rule must flag. `safe/`: the closest correct code, which a rule must not
  flag. Add a safe case for every vulnerable one (same shape, fixed).
- `<case>`: a short kebab-case name that says what differs, such as `string-concat` or
  `prepared-statement`. The extension must match the language (`.java`, `.kt`, `.py`, `.php`).
- `_parse/`: one trivial file per language that proves the parser works. It belongs to no rule.

Empty directories are not created in advance.

## Using the harness

`src/test-support/fixtures.ts` provides:

- `listFixtures({ language, category })`: the cases, vulnerable first.
- `runFixtures(cases, detect)`: runs `detect(fixture, source)` (returns the number of findings)
  and reports `missed` (vulnerable without a finding) and `falsePositives` (safe with a finding),
  plus true positive and true negative counts.
- `validateFixtureLayout()`: lists every path that breaks this convention. A test runs it, so a
  misplaced fixture fails the build.

A rule test passes when `missed` and `falsePositives` are both empty.
