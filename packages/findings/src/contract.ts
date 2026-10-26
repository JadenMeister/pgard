/**
 * PGARD common result contract (JSON v1).
 *
 * Every frontend (CLI, local web, reports) renders exactly this shape. Analyzers return
 * `AnalyzerOutput`; `scan-core` assembles a `ScanResult`. Anything that was not run is
 * recorded in `coverage`, never as "safe".
 */

export const SCHEMA_VERSION = "1.1" as const;

/**
 * Builds a value list from a `Record<T, true>`: a missing or extra member is a compile error, so
 * the lists below cannot drift from the union types they sit next to.
 */
function exhaustive<T extends string>(members: Record<T, true>): readonly T[] {
  return Object.keys(members) as T[];
}

/** User-selectable scan scopes. `scan` = code + history, `scan all` = code + history + web. */
export type ScanScope = "code" | "history" | "web";
export const SCAN_SCOPES = exhaustive<ScanScope>({ code: true, history: true, web: true });

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export const SEVERITIES = exhaustive<Severity>({
  critical: true,
  high: true,
  medium: true,
  low: true,
  info: true,
});

/** How strongly the evidence supports the finding. Never merged with severity into a score. */
export type Confidence = "high" | "medium" | "low";
export const CONFIDENCES = exhaustive<Confidence>({ high: true, medium: true, low: true });

export type FindingStatus = "confirmed" | "suspected" | "informational";
export const FINDING_STATUSES = exhaustive<FindingStatus>({
  confirmed: true,
  suspected: true,
  informational: true,
});

export type FindingCategory =
  | "injection"
  | "xss"
  | "ssrf"
  | "access_control"
  | "authentication"
  | "brute_force"
  | "cryptography"
  | "misconfiguration"
  | "csrf"
  | "file_handling"
  | "command_execution"
  | "secret_exposure";
export const FINDING_CATEGORIES = exhaustive<FindingCategory>({
  injection: true,
  xss: true,
  ssrf: true,
  access_control: true,
  authentication: true,
  brute_force: true,
  cryptography: true,
  misconfiguration: true,
  csrf: true,
  file_handling: true,
  command_execution: true,
  secret_exposure: true,
});

/**
 * - `completed`: the area ran to the end (findings may or may not exist).
 * - `partial`: only part of the area ran; `note` says what is missing.
 * - `not_tested`: the user selected the area but it could not run.
 * - `not_selected`: the user did not request the area.
 */
export type CoverageStatus = "completed" | "partial" | "not_tested" | "not_selected";
export const COVERAGE_STATUSES = exhaustive<CoverageStatus>({
  completed: true,
  partial: true,
  not_tested: true,
  not_selected: true,
});

export interface Coverage {
  /** Fine-grained area id, e.g. `source:typescript`, `history:secrets`, `web:anonymous`. */
  area: string;
  scope: ScanScope;
  status: CoverageStatus;
  ruleIds: string[];
  note: string | null;
}

export type LocationKind = "file" | "url" | "commit";
export const LOCATION_KINDS = exhaustive<LocationKind>({ file: true, url: true, commit: true });

export interface FindingLocation {
  kind: LocationKind;
  /** Repository-relative POSIX path. Never absolute. */
  path: string | null;
  line: number | null;
  url: string | null;
  commit: string | null;
}

/**
 * Where the finding sits. `test`: test or fixture code (see `isTestOrFixturePath`).
 * `vendored`: committed third-party dependency code such as `node_modules/` (see
 * `isVendoredPath`), shown as a suggestion. Such findings are kept and shown in their own group,
 * never dropped; headline counts use the other findings. Absent means regular project code.
 * Optional, so JSON v1 consumers that do not know it keep working.
 */
export type FindingContext = "test" | "vendored";
export const FINDING_CONTEXTS = exhaustive<FindingContext>({ test: true, vendored: true });

export interface FindingReferences {
  cwe: string[];
  owasp: string[];
  cve: string[];
}

export interface Finding {
  /** Stable fingerprint of rule + location + cause. Must not be derived from secret values. */
  id: string;
  ruleId: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
  location: FindingLocation;
  /** Redacted evidence. Never contains secret values, tokens, cookies or absolute paths. */
  evidence: string;
  impact: string;
  recommendation: string;
  references: FindingReferences;
  /** Scopes that produced this finding (kept when code and HTTP evidence are merged). */
  sources: ScanScope[];
  /**
   * Present only for findings in test or fixture code (`test`) or committed third-party code
   * (`vendored`); their confidence is capped at `low`.
   */
  context?: FindingContext;
}

/**
 * How many targets a rule examined, in one unit. `unit` is open-ended (a new unit is not a
 * schema change); today: `files`, `commits`, `blobs`, `pages`, `responses`, `unknown`.
 * `examined` is a real count or `null`, never an estimate; `null` always carries a `reason`.
 */
export interface RuleTargetCount {
  unit: string;
  examined: number | null;
  /** Why the count is unknown. Present exactly when `examined` is `null`. */
  reason: string | null;
}

/**
 * What one rule did in one coverage area (a rule that runs in several areas has one entry each).
 * Only rules that ran appear: a rule of an area that was not selected or not tested has no entry.
 */
export interface RuleStat {
  ruleId: string;
  /** The `Coverage.area` the rule ran in, e.g. `source:typescript`. */
  area: string;
  scope: ScanScope;
  /** The status of that area (`completed` or `partial`). */
  status: CoverageStatus;
  targets: RuleTargetCount[];
  /** Findings this rule reported in this area (before findings of several scopes are merged). */
  findings: number;
}

/**
 * - `checked`: a mapped rule ran to completion over everything it covers, for the languages
 *   present. It says the rule ran, never that the project is free of the weakness.
 * - `partial`: some mapped rules ran, but an area was partial or a language present is not covered.
 * - `not_checked`: no mapped rule exists, or none ran.
 */
export type StandardCheckState = "checked" | "partial" | "not_checked";
export const STANDARD_CHECK_STATES = exhaustive<StandardCheckState>({
  checked: true,
  partial: true,
  not_checked: true,
});

export interface StandardCoverageEntry {
  /** `A05:2025` or `CWE-79`. */
  id: string;
  title: string;
  /** CWE Top 25 rank; `null` for OWASP categories. */
  rank: number | null;
  state: StandardCheckState;
  /** Rules that ran and contribute to the state. */
  ruleIds: string[];
  /** Every rule in this PGARD version that maps to the entry, whether it ran or not. */
  mappedRuleIds: string[];
  /** One short sentence that explains the state. */
  reason: string;
}

export interface StandardsCoverage {
  owasp: StandardCoverageEntry[];
  cweTop25: StandardCoverageEntry[];
}

export interface AnalyzerOutput {
  findings: Finding[];
  coverage: Coverage[];
  /** Per-rule measurements; analyzers that cannot measure may omit it (scan-core then marks the counts unknown). */
  ruleStats?: RuleStat[];
}

export interface ScanTarget {
  /** `owner/name` of the verified GitHub repository. */
  repo: string | null;
  revision: string | null;
  webOrigin: string | null;
}

/**
 * Kept in JSON v1 for compatibility only. PGARD does not ship or query a vulnerability database,
 * so both fields are always `null`.
 */
export interface AdvisoryDbInfo {
  version: string | null;
  updatedAt: string | null;
}

export type AuthorizationCheckId =
  "repository" | "github_identity" | "owner_approval" | "current_access" | "contribution";
export const AUTHORIZATION_CHECK_IDS = exhaustive<AuthorizationCheckId>({
  repository: true,
  github_identity: true,
  owner_approval: true,
  current_access: true,
  contribution: true,
});

/** `unverifiable` blocks exactly like `failed`; it only differs in the reported reason. */
export type AuthorizationCheckStatus = "passed" | "failed" | "unverifiable";
export const AUTHORIZATION_CHECK_STATUSES = exhaustive<AuthorizationCheckStatus>({
  passed: true,
  failed: true,
  unverifiable: true,
});

export interface AuthorizationCheck {
  id: AuthorizationCheckId;
  status: AuthorizationCheckStatus;
  reason: string;
}

export type AuthorizationDecision = "allowed" | "blocked";
export const AUTHORIZATION_DECISIONS = exhaustive<AuthorizationDecision>({
  allowed: true,
  blocked: true,
});

export interface AuthorizationSummary {
  decision: AuthorizationDecision;
  checks: AuthorizationCheck[];
}

/**
 * - `completed`: every requested scope completed.
 * - `partial`: some requested coverage is `partial`/`not_tested` (e.g. `scan all` without a web target).
 * - `blocked`: the authorization gate refused the scan; no analysis ran.
 * - `failed`: an internal error stopped the scan.
 */
export type OverallStatus = "completed" | "partial" | "blocked" | "failed";
export const OVERALL_STATUSES = exhaustive<OverallStatus>({
  completed: true,
  partial: true,
  blocked: true,
  failed: true,
});

export interface ScanResult {
  schemaVersion: typeof SCHEMA_VERSION;
  scanId: string;
  startedAt: string;
  finishedAt: string;
  tool: { name: "pgard"; version: string };
  requestedScopes: ScanScope[];
  overallStatus: OverallStatus;
  target: ScanTarget;
  authorization: AuthorizationSummary;
  coverage: Coverage[];
  findings: Finding[];
  /** Deprecated: always `{ version: null, updatedAt: null }`. */
  advisoryDb: AdvisoryDbInfo;
  /** Added in 1.1. Absent in results written by 1.0. */
  ruleStats?: RuleStat[];
  /** Added in 1.1. Absent in results written by 1.0. */
  standardsCoverage?: StandardsCoverage;
}

/** A local HTTP target the user explicitly confirmed with `Y` after seeing its identity. */
export interface ConfirmedWebTarget {
  port: number;
  /** Always `http://127.0.0.1:<port>`. */
  origin: string;
  title: string | null;
  confirmedByUser: true;
}

export interface ScanRequest {
  /** Absolute path of the Git root chosen by the launcher. Never echoed into results. */
  projectRoot: string;
  scopes: ScanScope[];
  /** Required when `scopes` includes `web`; `null` records web as `not_tested`. */
  webTarget: ConfirmedWebTarget | null;
}
