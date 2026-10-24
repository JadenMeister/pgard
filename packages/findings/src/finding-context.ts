import type { Finding } from "./contract.js";

/** Directory names whose contents are test or fixture code (matched case-insensitively). */
const TEST_DIRECTORIES: ReadonlySet<string> = new Set([
  "__tests__",
  "__mocks__",
  "__fixtures__",
  "test",
  "tests",
  "fixtures",
  "testdata",
]);

/** `name.test.ts`, `name.spec.jsx`, ... and Go's `name_test.go`. */
const TEST_FILE_NAME = /\.(?:test|spec)\.[^./]+$|_test\.go$/i;

/**
 * Whether a repository-relative POSIX path is test or fixture code: a `*.test.*`, `*.spec.*` or
 * `*_test.go` file, or any file under a `__tests__/`, `__mocks__/`, `__fixtures__/`, `test/`,
 * `tests/`, `fixtures/` or `testdata/` directory.
 */
export function isTestOrFixturePath(filePath: string | null): boolean {
  if (filePath === null || filePath === "") return false;
  const segments = filePath.split("/");
  const name = segments.pop() ?? "";
  if (TEST_FILE_NAME.test(name)) return true;
  return segments.some((segment) => TEST_DIRECTORIES.has(segment.toLowerCase()));
}

export function isTestContextFinding(finding: Pick<Finding, "context">): boolean {
  return finding.context === "test";
}

/**
 * Marks a finding in test or fixture code with `context: "test"` and caps its confidence at
 * `low`: a match in a test is usually a deliberate sample, but it is still reported (rule,
 * severity and evidence unchanged) so a real value committed in a test is not lost.
 */
export function applyFindingContext(finding: Finding): Finding {
  if (!isTestContextFinding(finding) && !isTestOrFixturePath(finding.location.path)) {
    return finding;
  }
  return { ...finding, context: "test", confidence: "low" };
}

/** Splits findings into regular code (headline counts) and test or fixture code. */
export function splitFindingsByContext<T extends Pick<Finding, "context">>(
  findings: readonly T[],
): { primary: T[]; test: T[] } {
  const primary: T[] = [];
  const test: T[] = [];
  for (const finding of findings) (isTestContextFinding(finding) ? test : primary).push(finding);
  return { primary, test };
}
