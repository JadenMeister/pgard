import {
  AUTHORIZATION_CHECK_IDS,
  AUTHORIZATION_CHECK_STATUSES,
  CONFIDENCES,
  COVERAGE_STATUSES,
  FINDING_CATEGORIES,
  FINDING_CONTEXTS,
  FINDING_STATUSES,
  LOCATION_KINDS,
  OVERALL_STATUSES,
  SCAN_SCOPES,
  SCHEMA_VERSION,
  SEVERITIES,
  type AuthorizationCheck,
  type Coverage,
  type Finding,
  type FindingLocation,
  type ScanResult,
  type ScanScope,
} from "./contract.js";

/**
 * Single entry point for reading a scan result back (stored file, JSON output, CI input).
 * Policy: docs/RESULT_SCHEMA.md. The input is never trusted: the reader rebuilds a fresh object
 * from known fields only (unknown fields are dropped, so `__proto__` and friends never travel),
 * checks every enum against the constants in `contract.ts`, and never throws.
 */

export type ReadScanResultErrorCode =
  | "not_an_object"
  | "version_missing"
  | "version_malformed"
  | "version_unsupported_major"
  | "invalid_shape"
  | "too_large";

export interface ReadScanResultError {
  code: ReadScanResultErrorCode;
  message: string;
}

export type ReadScanResultOutcome =
  | {
      ok: true;
      /** Normalized: `schemaVersion` is the version this reader implements, not the input's. */
      result: ScanResult;
      /** The `schemaVersion` the input actually carried (same major, any minor). */
      sourceVersion: string;
    }
  | { ok: false; error: ReadScanResultError };

/** Limits that bound the work on hostile input. Real scans stay far below all of them. */
export const READ_LIMITS = {
  findings: 50_000,
  coverage: 1_000,
  /** Per-array cap for `ruleIds`, `references.*`, `sources`, `requestedScopes`, `checks`. */
  list: 1_000,
  /** Per-string cap (UTF-16 units). */
  string: 100_000,
} as const;

const SUPPORTED_MAJOR = Number(SCHEMA_VERSION.split(".")[0]);
const VERSION_PATTERN = /^(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})$/;

class ReadFailure extends Error {
  constructor(
    readonly code: ReadScanResultErrorCode,
    message: string,
  ) {
    super(message);
  }
}

function fail(code: ReadScanResultErrorCode, message: string): never {
  throw new ReadFailure(code, message);
}

type Obj = Record<string, unknown>;

function isObject(value: unknown): value is Obj {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Own property only: values inherited through a polluted prototype do not count. */
function field(obj: Obj, key: string): unknown {
  return Object.hasOwn(obj, key) ? obj[key] : undefined;
}

function object(value: unknown, path: string): Obj {
  if (!isObject(value)) fail("invalid_shape", `${path} must be an object.`);
  return value;
}

function str(value: unknown, path: string): string {
  if (typeof value !== "string") fail("invalid_shape", `${path} must be a string.`);
  if (value.length > READ_LIMITS.string) fail("too_large", `${path} is too long.`);
  return value;
}

function nullableStr(value: unknown, path: string): string | null {
  return value === null ? null : str(value, path);
}

function nullableLine(value: unknown, path: string): number | null {
  if (value === null) return null;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail("invalid_shape", `${path} must be a non-negative integer or null.`);
  }
  return value;
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], path: string): T {
  if (typeof value !== "string" || !(allowed as readonly string[]).includes(value)) {
    fail("invalid_shape", `${path} must be one of: ${allowed.join(", ")}.`);
  }
  return value as T;
}

function list(value: unknown, path: string, max: number): unknown[] {
  if (!Array.isArray(value)) fail("invalid_shape", `${path} must be an array.`);
  if (value.length > max) fail("too_large", `${path} has more than ${max} entries.`);
  return value;
}

function strings(value: unknown, path: string): string[] {
  return list(value, path, READ_LIMITS.list).map((item, i) => str(item, `${path}[${i}]`));
}

function scopes(value: unknown, path: string): ScanScope[] {
  return list(value, path, READ_LIMITS.list).map((item, i) =>
    oneOf(item, SCAN_SCOPES, `${path}[${i}]`),
  );
}

function readCoverage(value: unknown, path: string): Coverage {
  const o = object(value, path);
  return {
    area: str(field(o, "area"), `${path}.area`),
    scope: oneOf(field(o, "scope"), SCAN_SCOPES, `${path}.scope`),
    status: oneOf(field(o, "status"), COVERAGE_STATUSES, `${path}.status`),
    ruleIds: strings(field(o, "ruleIds"), `${path}.ruleIds`),
    note: nullableStr(field(o, "note"), `${path}.note`),
  };
}

function readLocation(value: unknown, path: string): FindingLocation {
  const o = object(value, path);
  return {
    kind: oneOf(field(o, "kind"), LOCATION_KINDS, `${path}.kind`),
    path: nullableStr(field(o, "path"), `${path}.path`),
    line: nullableLine(field(o, "line"), `${path}.line`),
    url: nullableStr(field(o, "url"), `${path}.url`),
    commit: nullableStr(field(o, "commit"), `${path}.commit`),
  };
}

function readFinding(value: unknown, path: string): Finding {
  const o = object(value, path);
  const refs = object(field(o, "references"), `${path}.references`);
  const finding: Finding = {
    id: str(field(o, "id"), `${path}.id`),
    ruleId: str(field(o, "ruleId"), `${path}.ruleId`),
    title: str(field(o, "title"), `${path}.title`),
    category: oneOf(field(o, "category"), FINDING_CATEGORIES, `${path}.category`),
    severity: oneOf(field(o, "severity"), SEVERITIES, `${path}.severity`),
    status: oneOf(field(o, "status"), FINDING_STATUSES, `${path}.status`),
    confidence: oneOf(field(o, "confidence"), CONFIDENCES, `${path}.confidence`),
    location: readLocation(field(o, "location"), `${path}.location`),
    evidence: str(field(o, "evidence"), `${path}.evidence`),
    impact: str(field(o, "impact"), `${path}.impact`),
    recommendation: str(field(o, "recommendation"), `${path}.recommendation`),
    references: {
      cwe: strings(field(refs, "cwe"), `${path}.references.cwe`),
      owasp: strings(field(refs, "owasp"), `${path}.references.owasp`),
      cve: strings(field(refs, "cve"), `${path}.references.cve`),
    },
    sources: scopes(field(o, "sources"), `${path}.sources`),
  };
  const context = field(o, "context");
  if (context !== undefined) {
    finding.context = oneOf(context, FINDING_CONTEXTS, `${path}.context`);
  }
  return finding;
}

function readAuthorization(value: unknown): ScanResult["authorization"] {
  const o = object(value, "authorization");
  const checks = list(field(o, "checks"), "authorization.checks", READ_LIMITS.list).map(
    (item, i): AuthorizationCheck => {
      const at = `authorization.checks[${i}]`;
      const c = object(item, at);
      return {
        id: oneOf(field(c, "id"), AUTHORIZATION_CHECK_IDS, `${at}.id`),
        status: oneOf(field(c, "status"), AUTHORIZATION_CHECK_STATUSES, `${at}.status`),
        reason: str(field(c, "reason"), `${at}.reason`),
      };
    },
  );
  return {
    decision: oneOf(field(o, "decision"), ["allowed", "blocked"], "authorization.decision"),
    checks,
  };
}

function checkVersion(input: Obj): string {
  const version = field(input, "schemaVersion");
  if (version === undefined || version === null) {
    fail("version_missing", "The result has no schemaVersion; it cannot be read safely.");
  }
  if (typeof version !== "string" || !VERSION_PATTERN.test(version)) {
    fail(
      "version_malformed",
      'schemaVersion must be a "major.minor" string such as "1.0"; refusing to guess.',
    );
  }
  const major = Number(version.split(".")[0]);
  if (major !== SUPPORTED_MAJOR) {
    fail(
      "version_unsupported_major",
      `schemaVersion ${version} is not supported: this PGARD reads major version ${SUPPORTED_MAJOR} only. Use a PGARD release that matches the file.`,
    );
  }
  return version;
}

function parse(input: unknown): ReadScanResultOutcome {
  if (!isObject(input)) fail("not_an_object", "A scan result must be a JSON object.");
  const sourceVersion = checkVersion(input);

  const tool = object(field(input, "tool"), "tool");
  const target = object(field(input, "target"), "target");
  const advisory = object(field(input, "advisoryDb"), "advisoryDb");
  const result: ScanResult = {
    schemaVersion: SCHEMA_VERSION,
    scanId: str(field(input, "scanId"), "scanId"),
    startedAt: str(field(input, "startedAt"), "startedAt"),
    finishedAt: str(field(input, "finishedAt"), "finishedAt"),
    tool: {
      name: oneOf(field(tool, "name"), ["pgard"], "tool.name"),
      version: str(field(tool, "version"), "tool.version"),
    },
    requestedScopes: scopes(field(input, "requestedScopes"), "requestedScopes"),
    overallStatus: oneOf(field(input, "overallStatus"), OVERALL_STATUSES, "overallStatus"),
    target: {
      repo: nullableStr(field(target, "repo"), "target.repo"),
      revision: nullableStr(field(target, "revision"), "target.revision"),
      webOrigin: nullableStr(field(target, "webOrigin"), "target.webOrigin"),
    },
    authorization: readAuthorization(field(input, "authorization")),
    coverage: list(field(input, "coverage"), "coverage", READ_LIMITS.coverage).map((item, i) =>
      readCoverage(item, `coverage[${i}]`),
    ),
    findings: list(field(input, "findings"), "findings", READ_LIMITS.findings).map((item, i) =>
      readFinding(item, `findings[${i}]`),
    ),
    advisoryDb: {
      version: nullableStr(field(advisory, "version"), "advisoryDb.version"),
      updatedAt: nullableStr(field(advisory, "updatedAt"), "advisoryDb.updatedAt"),
    },
  };
  return { ok: true, result, sourceVersion };
}

/** Validates `input` as a scan result. Never throws; every failure is a typed error. */
export function readScanResult(input: unknown): ReadScanResultOutcome {
  try {
    return parse(input);
  } catch (error) {
    if (error instanceof ReadFailure) {
      return { ok: false, error: { code: error.code, message: error.message } };
    }
    // Hostile input (throwing getters, revoked proxies): still a typed error, never a throw.
    return {
      ok: false,
      error: { code: "invalid_shape", message: "The result could not be read safely." },
    };
  }
}
