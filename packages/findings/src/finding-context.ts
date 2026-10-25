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
const CONFIG_FILE_NAME =
  /^\.env(?:\..*)?$|^\.npmrc$|^Dockerfile(?:\..*)?$|^(?!test_)(?:\w+_)?settings\.py$|^config\.py$|\.(?:ya?ml|tf|tfvars|properties|ini|toml|json|conf|cfg|xml)$/i;

/**
 * Whether a repository-relative POSIX path is test or fixture code. Classification is by path
 * only, never by content:
 * - a `*.test.*`, `*.spec.*` or `*_test.go` file, or
 * - any file under a `__tests__/`, `__mocks__/`, `__fixtures__/`, `fixtures/` or `testdata/`
 *   directory, or
 * - a file under `test/` or `tests/`, except config files there (`.env*`, `.npmrc`,
 *   `Dockerfile*`, `settings.py`/`*_settings.py`/`config.py`, `.yml`/`.yaml`, `.tf`, `.tfvars`,
 *   `.properties`, `.ini`, `.toml`, `.json`, `.conf`, `.cfg`, `.xml`), which may configure a real
 *   deployed test environment.
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

/**
 * Directory names whose contents are committed third-party dependency code (matched exactly,
 * case-sensitively: `Pods` is CocoaPods, while a lowercase `pods/` may be your own Kubernetes
 * configuration).
 */
export const VENDORED_DIRECTORIES: readonly string[] = [
  "node_modules",
  "bower_components",
  "jspm_packages",
  "vendor",
  "third_party",
  "Pods",
];
const VENDORED_DIRECTORY_SET: ReadonlySet<string> = new Set(VENDORED_DIRECTORIES);

/**
 * Whether a repository-relative POSIX path is committed third-party dependency code. By path
 * only, never by content: any directory segment is exactly `node_modules`, `bower_components`,
 * `jspm_packages`, `vendor`, `third_party` or `Pods`. Whole segments only, so `src/vendored.ts`
 * or `my_node_modules_x/` is not vendored. A path ending in `/` names a directory, so its last
 * segment counts too (`node_modules/`).
 */
export function isVendoredPath(filePath: string | null): boolean {
  if (filePath === null || filePath === "") return false;
  const segments = filePath.split("/");
  segments.pop(); // the file name (empty for a path ending in `/`)
  return segments.some((segment) => VENDORED_DIRECTORY_SET.has(segment));
}

export function isTestContextFinding(finding: Pick<Finding, "context">): boolean {
  return finding.context === "test";
}

export function isVendoredContextFinding(finding: Pick<Finding, "context">): boolean {
  return finding.context === "vendored";
}

/**
 * Marks findings by where they sit, capping their confidence at `low`; rule, severity and
 * evidence stay unchanged so nothing real is lost:
 * - committed third-party code (`isVendoredPath`) gets `context: "vendored"` and is shown as a
 *   suggestion: the user does not own that code and cannot fix it there;
 * - test or fixture code (`isTestOrFixturePath`) gets `context: "test"`: a match there is
 *   usually a deliberate sample, but a real value committed in a test is still exposed.
 * Vendored wins when a path is both (`node_modules/pkg/test/a.js`).
 */
export function applyFindingContext(finding: Finding): Finding {
  if (isVendoredContextFinding(finding) || isVendoredPath(finding.location.path)) {
    return { ...finding, context: "vendored", confidence: "low" };
  }
  if (!isTestContextFinding(finding) && !isTestOrFixturePath(finding.location.path)) {
    return finding;
  }
  return { ...finding, context: "test", confidence: "low" };
}

/**
 * Splits findings into regular code (headline counts), test or fixture code, and suggestions in
 * committed third-party (vendored) code.
 */
export function splitFindingsByContext<T extends Pick<Finding, "context">>(
  findings: readonly T[],
): { primary: T[]; test: T[]; vendored: T[] } {
  const primary: T[] = [];
  const test: T[] = [];
  const vendored: T[] = [];
  for (const finding of findings) {
    if (isVendoredContextFinding(finding)) vendored.push(finding);
    else if (isTestContextFinding(finding)) test.push(finding);
    else primary.push(finding);
  }
  return { primary, test, vendored };
}
