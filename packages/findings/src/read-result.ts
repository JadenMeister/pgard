import {
  AUTHORIZATION_CHECK_IDS,
  AUTHORIZATION_CHECK_STATUSES,
  CONFIDENCES,
  COVERAGE_STATUSES,
  FINDING_FIX_KINDS,
  MAX_FIX_DIFF_LENGTH,
  DEPENDENCY_SEVERITY_SOURCES,
  FINDING_CATEGORIES,
  FINDING_CONTEXTS,
  FINDING_STATUSES,
  INCREMENTAL_FULL_REASONS,
  SCAN_BASIS_AUTHORIZATIONS,
  SCAN_BASIS_MODES,
  SUPPRESSION_STATES,
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
  type BaselineSummary,
  type Coverage,
  type Finding,
  type FindingDependency,
  type FindingFix,
  type FindingLocation,
  type FindingReferences,
  type FindingSuppression,
  type IncrementalAreaInfo,
  type IncrementalInfo,
  type RuleStat,
  type RuleTargetCount,
  type StandardBreadth,
  type StandardCoverageEntry,
  type StandardsCoverage,
  type ScanBasis,
  type ScanResult,
  type ScanScope,
  type ScanTarget,
  type Severity,
  type SuppressionEntryResult,
  type SuppressionSummary,
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
    suppressions: true,
    baseline: true,
    ruleStats: true,
    standardsCoverage: true,
    incremental: true,
    scanBasis: true,
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
    suppression: true,
    inBaseline: true,
    dependency: true,
    fix: true,
  } satisfies Record<keyof Finding, true>,
  fix: { kind: true, diff: true, confidence: true, reason: true } satisfies Record<
    keyof FindingFix,
    true
  >,
  location: {
    kind: true,
    path: true,
    line: true,
    url: true,
    commit: true,
  } satisfies Record<keyof FindingLocation, true>,
  references: { cwe: true, owasp: true, cve: true, cert: true } satisfies Record<
    keyof FindingReferences,
    true
  >,
  coverage: {
    area: true,
    scope: true,
    status: true,
    ruleIds: true,
    note: true,
    walkedDirectories: true,
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

const SUPPRESSION_SOURCES: readonly FindingSuppression["source"][] = ["pgard.config.json"];
const MAX_COUNT = 2_000_000_000;
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
  const entry: Coverage = {
    area: str(field(o, "area"), `${path}.area`),
    scope: oneOf(field(o, "scope"), SCAN_SCOPES, `${path}.scope`),
    status: oneOf(field(o, "status"), COVERAGE_STATUSES, `${path}.status`),
    ruleIds: strings(field(o, "ruleIds"), `${path}.ruleIds`),
    note: nullableStr(field(o, "note"), `${path}.note`),
  };
  const walked = field(o, "walkedDirectories");
  if (walked !== undefined) {
    const w = object(walked, `${path}.walkedDirectories`);
    entry.walkedDirectories = {
      paths: strings(field(w, "paths"), `${path}.walkedDirectories.paths`),
      complete: bool(field(w, "complete"), `${path}.walkedDirectories.complete`),
    };
  }
  return entry;
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

function nullableCount(value: unknown, path: string): number | null {
  return value === null ? null : count(value, path);
}

function nullableReason(value: unknown, path: string): IncrementalAreaInfo["reason"] {
  return value === null ? null : oneOf(value, INCREMENTAL_FULL_REASONS, path);
}

const SCAN_BASIS_REASON = /^[a-z][a-z_]{0,63}$/;

function readScanBasis(value: unknown): ScanBasis {
  const o = object(value, "scanBasis");
  const mode = oneOf(field(o, "mode"), SCAN_BASIS_MODES, "scanBasis.mode");
  const authorization = oneOf(
    field(o, "authorization"),
    SCAN_BASIS_AUTHORIZATIONS,
    "scanBasis.authorization",
  );
  const reasonValue = field(o, "reason");
  const reason = reasonValue === null ? null : str(reasonValue, "scanBasis.reason");
  if (reason !== null && !SCAN_BASIS_REASON.test(reason)) {
    fail("invalid_shape", "scanBasis.reason must be a lowercase code such as no_approval.");
  }
  // A code-only scan never proves authorization.
  if (mode === "code_only" && authorization !== "not_verified") {
    fail("invalid_shape", "scanBasis.authorization must be not_verified for a code-only scan.");
  }
  if ((authorization === "verified") !== (reason === null)) {
    fail("invalid_shape", "scanBasis.reason must be null exactly when authorization is verified.");
  }
  return { mode, authorization, reason };
}

/**
 * `scanBasis` must agree with the rest of the result: "verified" only for a scan the gate
 * allowed with every check passed, and "code_only" only for a blocked, code-only, unverified
 * scan. Anything else would let a crafted file claim an authorization it never had.
 */
function checkScanBasis(basis: ScanBasis, result: ScanResult): void {
  const { decision, checks } = result.authorization;
  if (basis.authorization === "verified") {
    const passed = new Set(
      checks.filter((check) => check.status === "passed").map((check) => check.id),
    );
    const allPassed = AUTHORIZATION_CHECK_IDS.every((id) => passed.has(id));
    if (decision !== "allowed" || !allPassed) {
      fail(
        "invalid_shape",
        "scanBasis.authorization is verified only when the gate allowed the scan with every check passed.",
      );
    }
  }
  // An authorized-mode scan that was not verified never ran the analyzers: the gate blocked it
  // or failed. Anything else is a code-only result with its label edited away.
  if (basis.mode === "authorized" && basis.authorization === "not_verified") {
    const stopped = result.overallStatus === "blocked" || result.overallStatus === "failed";
    if (!stopped || result.findings.length > 0) {
      fail(
        "invalid_shape",
        "scanBasis authorized and not_verified needs overallStatus blocked or failed and no findings.",
      );
    }
  }
  if (basis.mode === "code_only") {
    const codeOnlyScopes =
      result.requestedScopes.length === 1 && result.requestedScopes[0] === "code";
    if (decision !== "blocked" || !codeOnlyScopes) {
      fail(
        "invalid_shape",
        'scanBasis.mode code_only needs authorization.decision blocked and requestedScopes ["code"].',
      );
    }
  }
}

function readIncrementalArea(value: unknown, path: string): IncrementalAreaInfo | null {
  if (value === null) return null;
  const o = object(value, path);
  return {
    mode: oneOf(field(o, "mode"), ["incremental", "full"] as const, `${path}.mode`),
    reason: nullableReason(field(o, "reason"), `${path}.reason`),
  };
}

function readIncrementalInfo(value: unknown): IncrementalInfo {
  const o = object(value, "incremental");
  const basedOnValue = field(o, "basedOn");
  let basedOn: IncrementalInfo["basedOn"] = null;
  if (basedOnValue !== null) {
    const b = object(basedOnValue, "incremental.basedOn");
    basedOn = {
      scanId: str(field(b, "scanId"), "incremental.basedOn.scanId"),
      revision: nullableStr(field(b, "revision"), "incremental.basedOn.revision"),
    };
  }
  return {
    used: bool(field(o, "used"), "incremental.used"),
    reason: nullableReason(field(o, "reason"), "incremental.reason"),
    basedOn,
    filesRescanned: nullableCount(field(o, "filesRescanned"), "incremental.filesRescanned"),
    filesReused: nullableCount(field(o, "filesReused"), "incremental.filesReused"),
    commitsScanned: nullableCount(field(o, "commitsScanned"), "incremental.commitsScanned"),
    commitsReused: nullableCount(field(o, "commitsReused"), "incremental.commitsReused"),
    code: readIncrementalArea(field(o, "code"), "incremental.code"),
    history: readIncrementalArea(field(o, "history"), "incremental.history"),
  };
}

/**
 * Validates a list of findings with the same checks as a result's findings (used for the cached
 * findings of an incremental state). `null` when anything is wrong; never throws.
 */
export function readFindingList(input: unknown): Finding[] | null {
  budget = READ_LIMITS.entries;
  try {
    return list(input, "findings", READ_LIMITS.findings, readFinding);
  } catch {
    return null;
  }
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
  const cert = field(refs, "cert");
  if (cert !== undefined) finding.references.cert = strings(cert, `${path}.references.cert`);
  const context = field(o, "context");
  if (context !== undefined) {
    finding.context = oneOf(context, FINDING_CONTEXTS, `${path}.context`);
  }
  const suppression = field(o, "suppression");
  if (suppression !== undefined)
    finding.suppression = readSuppression(suppression, `${path}.suppression`);
  const dependency = field(o, "dependency");
  if (dependency !== undefined) {
    finding.dependency = readDependency(dependency, `${path}.dependency`);
  }
  const fix = field(o, "fix");
  if (fix !== undefined) finding.fix = readFix(fix, `${path}.fix`);
  const inBaseline = field(o, "inBaseline");
  if (inBaseline !== undefined) {
    if (inBaseline !== true) fail("invalid_shape", `${path}.inBaseline must be true when present.`);
    finding.inBaseline = true;
  }
  return finding;
}

function readFix(value: unknown, path: string): FindingFix {
  const o = object(value, path);
  const kind = oneOf(field(o, "kind"), FINDING_FIX_KINDS, `${path}.kind`);
  const diff = field(o, "diff");
  const reason = field(o, "reason");
  const fix: FindingFix = {
    kind,
    confidence: oneOf(field(o, "confidence"), CONFIDENCES, `${path}.confidence`),
  };
  if (kind === "diff") {
    if (typeof diff !== "string" || diff.length === 0) {
      fail("invalid_shape", `${path}.diff must be a non-empty string when kind is diff.`);
    }
    if (diff.length > MAX_FIX_DIFF_LENGTH) fail("too_large", `${path}.diff is too long.`);
    fix.diff = diff;
  } else if (diff !== undefined) {
    fail("invalid_shape", `${path}.diff is only allowed when kind is diff.`);
  }
  if (reason !== undefined) {
    if (kind === "diff") fail("invalid_shape", `${path}.reason is only allowed for guidance.`);
    fix.reason = str(reason, `${path}.reason`);
  }
  return fix;
}

function readDependency(value: unknown, path: string): FindingDependency {
  const o = object(value, path);
  const dev = field(o, "dev");
  const direct = field(o, "direct");
  const score = field(o, "score");
  const vector = field(o, "vector");
  if (score !== undefined && !(typeof score === "number" && score >= 0 && score <= 10)) {
    fail("invalid_shape", `${path}.score must be a number from 0 to 10.`);
  }
  return {
    ecosystem: str(field(o, "ecosystem"), `${path}.ecosystem`),
    name: str(field(o, "name"), `${path}.name`),
    version: str(field(o, "version"), `${path}.version`),
    ...(dev === undefined ? {} : { dev: bool(dev, `${path}.dev`) }),
    ...(direct === undefined ? {} : { direct: bool(direct, `${path}.direct`) }),
    advisoryId: str(field(o, "advisoryId"), `${path}.advisoryId`),
    aliases: strings(field(o, "aliases"), `${path}.aliases`),
    affectedRange: str(field(o, "affectedRange"), `${path}.affectedRange`),
    fixedVersions: strings(field(o, "fixedVersions"), `${path}.fixedVersions`),
    severitySource: oneOf(
      field(o, "severitySource"),
      DEPENDENCY_SEVERITY_SOURCES,
      `${path}.severitySource`,
    ),
    ...(score === undefined ? {} : { score: score as number }),
    ...(vector === undefined ? {} : { vector: str(vector, `${path}.vector`) }),
  };
}

function count(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0 || value > MAX_COUNT) {
    fail("invalid_shape", `${path} must be a non-negative integer.`);
  }
  return value;
}

function bool(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") fail("invalid_shape", `${path} must be true or false.`);
  return value;
}

function readSuppression(value: unknown, path: string): FindingSuppression {
  const o = object(value, path);
  const expires = field(o, "expires");
  return {
    reason: str(field(o, "reason"), `${path}.reason`),
    ...(expires === undefined ? {} : { expires: str(expires, `${path}.expires`) }),
    source: oneOf(field(o, "source"), SUPPRESSION_SOURCES, `${path}.source`),
  };
}

function readSuppressionEntry(value: unknown, path: string): SuppressionEntryResult {
  const o = object(value, path);
  const expires = field(o, "expires");
  return {
    ruleId: str(field(o, "ruleId"), `${path}.ruleId`),
    path: str(field(o, "path"), `${path}.path`),
    reason: str(field(o, "reason"), `${path}.reason`),
    ...(expires === undefined ? {} : { expires: str(expires, `${path}.expires`) }),
    state: oneOf(field(o, "state"), SUPPRESSION_STATES, `${path}.state`),
    matched: count(field(o, "matched"), `${path}.matched`),
    wildcard: bool(field(o, "wildcard"), `${path}.wildcard`),
    farExpiry:
      field(o, "farExpiry") === undefined
        ? false
        : bool(field(o, "farExpiry"), `${path}.farExpiry`),
  };
}

function readSeverityCounts(value: unknown, path: string): Record<Severity, number> {
  const o = object(value, path);
  return {
    critical: count(field(o, "critical"), `${path}.critical`),
    high: count(field(o, "high"), `${path}.high`),
    medium: count(field(o, "medium"), `${path}.medium`),
    low: count(field(o, "low"), `${path}.low`),
    info: count(field(o, "info"), `${path}.info`),
  };
}

function readSuppressionSummary(value: unknown): SuppressionSummary {
  const o = object(value, "suppressions");
  return {
    source: oneOf(field(o, "source"), SUPPRESSION_SOURCES, "suppressions.source"),
    suppressed: count(field(o, "suppressed"), "suppressions.suppressed"),
    critical: count(field(o, "critical"), "suppressions.critical"),
    bySeverity: readSeverityCounts(field(o, "bySeverity"), "suppressions.bySeverity"),
    entries: list(field(o, "entries"), "suppressions.entries", 1_000, readSuppressionEntry),
    incomplete: bool(field(o, "incomplete"), "suppressions.incomplete"),
  };
}

function readBaselineSummary(value: unknown): BaselineSummary {
  const o = object(value, "baseline");
  return {
    setAt: str(field(o, "setAt"), "baseline.setAt"),
    scanId: str(field(o, "scanId"), "baseline.scanId"),
    revision: nullableStr(field(o, "revision"), "baseline.revision"),
    total: count(field(o, "total"), "baseline.total"),
    matched: count(field(o, "matched"), "baseline.matched"),
    new: count(field(o, "new"), "baseline.new"),
    newInUncertainAreas: count(field(o, "newInUncertainAreas"), "baseline.newInUncertainAreas"),
    toolVersionChanged: bool(field(o, "toolVersionChanged"), "baseline.toolVersionChanged"),
  };
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
  const suppressions = field(input, "suppressions");
  if (suppressions !== undefined) result.suppressions = readSuppressionSummary(suppressions);
  const baseline = field(input, "baseline");
  if (baseline !== undefined) result.baseline = readBaselineSummary(baseline);
  // Added in 1.1: absent in older results, and a present-but-malformed value is refused like any
  // other field (a 1.0 result never carries them, so absent is the only old-version shape).
  const ruleStats = field(input, "ruleStats");
  if (ruleStats !== undefined) {
    result.ruleStats = list(ruleStats, "ruleStats", READ_LIMITS.ruleStats, readRuleStat);
  }
  const standards = field(input, "standardsCoverage");
  if (standards !== undefined) result.standardsCoverage = readStandardsCoverage(standards);
  // Added in 1.2: absent in older results.
  const incremental = field(input, "incremental");
  if (incremental !== undefined) result.incremental = readIncrementalInfo(incremental);
  // Added in 1.7: absent in older results (a reader treats absent as an authorized scan).
  // Required from 1.7 on, so removing it from a file cannot drop the code-only label.
  const scanBasis = field(input, "scanBasis");
  if (scanBasis === undefined && Number(sourceVersion.split(".")[1]) >= 7) {
    fail("invalid_shape", `scanBasis is required in schemaVersion ${sourceVersion}.`);
  }
  if (scanBasis !== undefined) {
    result.scanBasis = readScanBasis(scanBasis);
    checkScanBasis(result.scanBasis, result);
  }
  // Before 1.7 a blocked scan never carried findings (nothing ran after the gate). Blocked with
  // findings is the shape of a code-only result: with the version lowered and `scanBasis`
  // removed it would read as an authorized scan, so it is refused (#427).
  if (
    scanBasis === undefined &&
    Number(sourceVersion.split(".")[1]) < 7 &&
    result.authorization.decision === "blocked" &&
    result.findings.length > 0
  ) {
    fail(
      "invalid_shape",
      `A result with a blocked authorization decision and findings must carry scanBasis (schemaVersion ${sourceVersion} has none).`,
    );
  }
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
