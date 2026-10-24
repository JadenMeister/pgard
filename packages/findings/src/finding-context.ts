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

/**
 * Directory names that may also hold a deployed "test" environment (`deploy/test/values.yaml`,
 * `environments/test/.env`); config files under them are not treated as test code.
 */
const ENVIRONMENT_DIRECTORIES: ReadonlySet<string> = new Set(["test", "tests"]);

/** `name.test.ts`, `name.spec.jsx`, ... and Go's `name_test.go`. */
const TEST_FILE_NAME = /\.(?:test|spec)\.[^./]+$|_test\.go$/i;

/** Environment, config and infrastructure files: `.env*`, YAML, Terraform, properties, ... */
const CONFIG_FILE_NAME = /^\.env(?:\..*)?$|\.(?:ya?ml|tf|tfvars|properties|ini|toml|json)$/i;

/**
 * Whether a repository-relative POSIX path is test or fixture code. Classification is by path
 * only, never by content:
 * - a `*.test.*`, `*.spec.*` or `*_test.go` file, or
 * - any file under a `__tests__/`, `__mocks__/`, `__fixtures__/`, `fixtures/` or `testdata/`
 *   directory, or
 * - a file under `test/` or `tests/`, except config files there (`.env*`, `.yml`/`.yaml`, `.tf`,
 *   `.tfvars`, `.properties`, `.ini`, `.toml`, `.json`), which may configure a real deployed
 *   test environment.
 */
export function isTestOrFixturePath(filePath: string | null): boolean {
  if (filePath === null || filePath === "") return false;
  const segments = filePath.split("/");
  const name = segments.pop() ?? "";
  if (TEST_FILE_NAME.test(name)) return true;
  const isConfig = CONFIG_FILE_NAME.test(name);
  return segments.some((segment) => {
    const directory = segment.toLowerCase();
    return TEST_DIRECTORIES.has(directory) && !(isConfig && ENVIRONMENT_DIRECTORIES.has(directory));
  });
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
