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
  STANDARD_CHECK_STATES,
  AUTHORIZATION_DECISIONS,
  type AdvisoryDbInfo,
  type AuthorizationCheck,
  type AuthorizationSummary,
  type Coverage,
  type Finding,
  type FindingLocation,
  type FindingReferences,
  type RuleStat,
  type RuleTargetCount,
  type StandardBreadth,
  type StandardCoverageEntry,
  type StandardsCoverage,
  type ScanResult,
  type ScanScope,
  type ScanTarget,
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
  /** Rule stats: one entry per rule and area. */
  ruleStats: 10_000,
  /** Entries per standard (OWASP has 10, the CWE Top 25 has 25). */
  standardsEntries: 200,
  /** Per-array cap for `ruleIds`, `references.*`, `sources`, `requestedScopes`, `checks`. */
  list: 1_000,
  /** Per-string cap (UTF-16 units). */
  string: 100_000,
  /** Cap on the entries of all arrays together (findings, coverage and every inner list). */
  entries: 1_000_000,
} as const;

/**
 * Compile-time key lists: adding a field to a contract type without listing it here (and so
 * without updating the reader) is a type error. Optional fields are what this really guards,
 * because required ones are already enforced by the object literals below.
 */
export const READER_KEYS = {
  scanResult: {
    schemaVersion: true,
    scanId: true,
    startedAt: true,
    finishedAt: true,
    tool: true,
    requestedScopes: true,
    overallStatus: true,
    target: true,
    authorization: true,
    coverage: true,
    findings: true,
    advisoryDb: true,
    ruleStats: true,
    standardsCoverage: true,
  } satisfies Record<keyof ScanResult, true>,
  finding: {
    id: true,
    ruleId: true,
    title: true,
    category: true,
    severity: true,
    status: true,
    confidence: true,
    location: true,
    evidence: true,
    impact: true,
    recommendation: true,
    references: true,
    sources: true,
    context: true,
  } satisfies Record<keyof Finding, true>,
  location: {
    kind: true,
    path: true,
    line: true,
    url: true,
    commit: true,
  } satisfies Record<keyof FindingLocation, true>,
  references: { cwe: true, owasp: true, cve: true } satisfies Record<keyof FindingReferences, true>,
  coverage: {
    area: true,
    scope: true,
    status: true,
    ruleIds: true,
    note: true,
  } satisfies Record<keyof Coverage, true>,
  target: { repo: true, revision: true, webOrigin: true } satisfies Record<keyof ScanTarget, true>,
  authorization: { decision: true, checks: true } satisfies Record<
    keyof AuthorizationSummary,
    true
  >,
  check: { id: true, status: true, reason: true } satisfies Record<keyof AuthorizationCheck, true>,
  advisoryDb: { version: true, updatedAt: true } satisfies Record<keyof AdvisoryDbInfo, true>,
  ruleStat: {
    ruleId: true,
    area: true,
    scope: true,
    status: true,
    targets: true,
    findings: true,
  } satisfies Record<keyof RuleStat, true>,
  ruleTarget: { unit: true, examined: true, reason: true } satisfies Record<
    keyof RuleTargetCount,
    true
  >,
  standardsCoverage: { owasp: true, cweTop25: true } satisfies Record<
    keyof StandardsCoverage,
    true
  >,
  standardEntry: {
    id: true,
    title: true,
    rank: true,
    state: true,
    breadth: true,
    ruleIds: true,
    mappedRuleIds: true,
    reason: true,
  } satisfies Record<keyof StandardCoverageEntry, true>,
  tool: { name: true, version: true } satisfies Record<keyof ScanResult["tool"], true>,
};

const TOOL_NAMES: readonly ScanResult["tool"]["name"][] = ["pgard"];
const SUPPORTED_MAJOR = Number(SCHEMA_VERSION.split(".")[0]);
const VERSION_PATTERN = /^(0|[1-9]\d{0,5})\.(0|[1-9]\d{0,5})$/;

/**
 * Errors this module raised itself, tracked by identity so the catch block never runs
 * `instanceof` (which would call a hostile proxy's `getPrototypeOf` trap).
 */
const failures = new WeakMap<object, ReadScanResultError>();

function fail(code: ReadScanResultErrorCode, message: string): never {
  const error = new Error(message);
  failures.set(error, { code, message });
  throw error;
}

/** Remaining array entries this read may visit; reset per call (the reader is synchronous). */
let budget = 0;

type Obj = Record<string, unknown>;

function isObject(value: unknown): value is Obj {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Reads an own data property. Inherited values do not count and accessors are refused without
 * being called, so input code never runs.
 */
function field(obj: Obj, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(obj, key);
  if (descriptor === undefined) return undefined;
  if (!("value" in descriptor)) fail("invalid_shape", `${key} must be a plain data property.`);
  return descriptor.value;
}

function object(value: unknown, path: string): Obj {
  if (!isObject(value)) fail("invalid_shape", `${path} must be an object.`);
  return value;
}

/**
 * Strings are length-capped, not sanitized: evidence, titles and notes may contain any
 * characters, and escaping them for HTML, terminals or SARIF is the consumer's job.
 */
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
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    fail("invalid_shape", `${path} must be an integer of at least 1, or null.`);
  }
  return value;
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], path: string): T {
  if (typeof value !== "string" || !(allowed as readonly string[]).includes(value)) {
    fail("invalid_shape", `${path} must be one of: ${allowed.join(", ")}.`);
  }
  return value as T;
}

/**
 * Reads an array into a fresh one. `length` is read once and capped, then elements are read by
 * index as own data properties (a hole or accessor reads as `undefined` and fails in `read`).
 * No `map`, so holes and `Symbol.species` cannot change the outcome.
 */
function list<T>(
  value: unknown,
  path: string,
  max: number,
  read: (item: unknown, path: string) => T,
): T[] {
  if (!Array.isArray(value)) fail("invalid_shape", `${path} must be an array.`);
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  const length = lengthDescriptor && "value" in lengthDescriptor ? lengthDescriptor.value : null;
  if (typeof length !== "number" || !Number.isSafeInteger(length) || length < 0) {
    fail("invalid_shape", `${path} has no readable length.`);
  }
  if (length > max) fail("too_large", `${path} has more than ${max} entries.`);
  budget -= length;
  if (budget < 0) fail("too_large", "The result has too many array entries in total.");
  const out: T[] = [];
  for (let i = 0; i < length; i++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(i));
    const item = descriptor && "value" in descriptor ? descriptor.value : undefined;
    out.push(read(item, `${path}[${i}]`));
  }
  return out;
}

function strings(value: unknown, path: string): string[] {
  return list(value, path, READ_LIMITS.list, str);
}

function scopes(value: unknown, path: string): ScanScope[] {
  return list(value, path, READ_LIMITS.list, (item, at) => oneOf(item, SCAN_SCOPES, at));
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

function count(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    fail("invalid_shape", `${path} must be a non-negative integer.`);
  }
  return value;
}

function readRuleTarget(value: unknown, path: string): RuleTargetCount {
  const o = object(value, path);
  const examinedValue = field(o, "examined");
  const examined = examinedValue === null ? null : count(examinedValue, `${path}.examined`);
  const reason = nullableStr(field(o, "reason"), `${path}.reason`);
  if (examined === null && reason === null) {
    fail("invalid_shape", `${path} has no count and no reason; an unknown count needs a reason.`);
  }
  if (examined !== null && reason !== null) {
    fail(
      "invalid_shape",
      `${path} has a count and a reason; a reason is only for an unknown count.`,
    );
  }
  return { unit: str(field(o, "unit"), `${path}.unit`), examined, reason };
}

function readRuleStat(value: unknown, path: string): RuleStat {
  const o = object(value, path);
  return {
    ruleId: str(field(o, "ruleId"), `${path}.ruleId`),
    area: str(field(o, "area"), `${path}.area`),
    scope: oneOf(field(o, "scope"), SCAN_SCOPES, `${path}.scope`),
    status: oneOf(field(o, "status"), COVERAGE_STATUSES, `${path}.status`),
    targets: list(field(o, "targets"), `${path}.targets`, READ_LIMITS.list, readRuleTarget),
    findings: count(field(o, "findings"), `${path}.findings`),
  };
}

function readStandardEntry(value: unknown, path: string): StandardCoverageEntry {
  const o = object(value, path);
  const rank = field(o, "rank");
  const breadthValue = field(o, "breadth");
  let breadth: StandardBreadth | null = null;
  if (breadthValue !== null) {
    const b = object(breadthValue, `${path}.breadth`);
    breadth = {
      cwesWithRules: count(field(b, "cwesWithRules"), `${path}.breadth.cwesWithRules`),
      cwesInCategory: count(field(b, "cwesInCategory"), `${path}.breadth.cwesInCategory`),
    };
  }
  return {
    id: str(field(o, "id"), `${path}.id`),
    title: str(field(o, "title"), `${path}.title`),
    rank: rank === null ? null : count(rank, `${path}.rank`),
    state: oneOf(field(o, "state"), STANDARD_CHECK_STATES, `${path}.state`),
    breadth,
    ruleIds: strings(field(o, "ruleIds"), `${path}.ruleIds`),
    mappedRuleIds: strings(field(o, "mappedRuleIds"), `${path}.mappedRuleIds`),
    reason: str(field(o, "reason"), `${path}.reason`),
  };
}

function readStandardsCoverage(value: unknown): StandardsCoverage {
  const o = object(value, "standardsCoverage");
  const entries = (key: "owasp" | "cweTop25") =>
    list(
      field(o, key),
      `standardsCoverage.${key}`,
      READ_LIMITS.standardsEntries,
      readStandardEntry,
    );
  return { owasp: entries("owasp"), cweTop25: entries("cweTop25") };
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

function readCheck(value: unknown, path: string): AuthorizationCheck {
  const c = object(value, path);
  return {
    id: oneOf(field(c, "id"), AUTHORIZATION_CHECK_IDS, `${path}.id`),
    status: oneOf(field(c, "status"), AUTHORIZATION_CHECK_STATUSES, `${path}.status`),
    reason: str(field(c, "reason"), `${path}.reason`),
  };
}

function readAuthorization(value: unknown): ScanResult["authorization"] {
  const o = object(value, "authorization");
  return {
    decision: oneOf(field(o, "decision"), AUTHORIZATION_DECISIONS, "authorization.decision"),
    checks: list(field(o, "checks"), "authorization.checks", READ_LIMITS.list, readCheck),
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
      name: oneOf(field(tool, "name"), TOOL_NAMES, "tool.name"),
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
    coverage: list(field(input, "coverage"), "coverage", READ_LIMITS.coverage, readCoverage),
    findings: list(field(input, "findings"), "findings", READ_LIMITS.findings, readFinding),
    advisoryDb: {
      version: nullableStr(field(advisory, "version"), "advisoryDb.version"),
      updatedAt: nullableStr(field(advisory, "updatedAt"), "advisoryDb.updatedAt"),
    },
  };
  // Added in 1.1: absent in older results, and a present-but-malformed value is refused like any
  // other field (a 1.0 result never carries them, so absent is the only old-version shape).
  const ruleStats = field(input, "ruleStats");
  if (ruleStats !== undefined) {
    result.ruleStats = list(ruleStats, "ruleStats", READ_LIMITS.ruleStats, readRuleStat);
  }
  const standards = field(input, "standardsCoverage");
  if (standards !== undefined) result.standardsCoverage = readStandardsCoverage(standards);
  const seen = new Set<string>();
  for (const [i, finding] of result.findings.entries()) {
    if (seen.has(finding.id)) {
      fail("invalid_shape", `findings[${i}].id duplicates an earlier finding id.`);
    }
    seen.add(finding.id);
  }
  return { ok: true, result, sourceVersion };
}

/**
 * Validates `input` as a scan result. Never throws; every failure is a typed error. Callers
 * should cap the file size before `JSON.parse`; this function bounds the work after parsing.
 */
export function readScanResult(input: unknown): ReadScanResultOutcome {
  budget = READ_LIMITS.entries;
  try {
    return parse(input);
  } catch (error) {
    const info = typeof error === "object" && error !== null ? failures.get(error) : undefined;
    if (info !== undefined) return { ok: false, error: info };
    // Hostile input (throwing proxy traps, revoked proxies): still a typed error, never a throw.
    return {
      ok: false,
      error: { code: "invalid_shape", message: "The result could not be read safely." },
    };
  }
}
