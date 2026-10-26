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

/** Where a suppression came from. Only the repository config file can suppress a finding. */
export type SuppressionSource = "pgard.config.json";

/**
 * A finding that matched an active `suppressions` entry of `pgard.config.json`. The finding stays
 * in the result: nothing is deleted, only grouped apart (and counted in `ScanResult.suppressions`).
 */
export interface FindingSuppression {
  /** The entry's reason, as written in the (untrusted) config file. */
  reason: string;
  /** `YYYY-MM-DD`, when the entry has one. */
  expires?: string;
  source: SuppressionSource;
}

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
  /** Present only when an active suppression of `pgard.config.json` matched this finding. */
  suppression?: FindingSuppression;
  /**
   * `true` only when the repository has a baseline (`pgard baseline set`) that contains this
   * finding (same identity as the scan comparison). Absent: not in the baseline, or no baseline.
   */
  inBaseline?: true;
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
 * What a scan can say about a standards entry. None of these states means "safe" or "category
 * covered": they say whether PGARD rules that map to the entry ran.
 *
 * - `rules_ran`: every scope that has a mapped rule ran, all contributing areas completed, no
 *   code area was partial, and every language present is covered by a completed mapped rule. It
 *   still says nothing about how much of the entry the rules cover (see `breadth`).
 * - `rules_partial`: some mapped rules ran, but something was partial, missing or uncovered.
 * - `not_run`: rules map to the entry, but none ran in this scan.
 * - `no_rules`: no PGARD rule maps to the entry.
 */
export type StandardCheckState = "rules_ran" | "rules_partial" | "not_run" | "no_rules";
export const STANDARD_CHECK_STATES = exhaustive<StandardCheckState>({
  rules_ran: true,
  rules_partial: true,
  not_run: true,
  no_rules: true,
});

/** How much of an OWASP category's mapped CWE list PGARD has any rule for. */
export interface StandardBreadth {
  /** CWEs of the category's "List of Mapped CWEs" that at least one PGARD rule lists. */
  cwesWithRules: number;
  cwesInCategory: number;
}

export interface StandardCoverageEntry {
  /** `A05:2025` or `CWE-79`. */
  id: string;
  title: string;
  /** CWE Top 25 rank; `null` for OWASP categories. */
  rank: number | null;
  state: StandardCheckState;
  /** OWASP categories only; `null` for CWE Top 25 entries (a CWE is one weakness, 1 of 1). */
  breadth: StandardBreadth | null;
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

export type SuppressionState = "active" | "expired";
export const SUPPRESSION_STATES = exhaustive<SuppressionState>({ active: true, expired: true });

/** One `suppressions` entry of the config and what it did in this scan. */
export interface SuppressionEntryResult {
  ruleId: string;
  path: string;
  reason: string;
  expires?: string;
  /** `expired`: past its date, not applied. */
  state: SuppressionState;
  /** Findings this entry matches (0 for an expired entry; findings matching it are not hidden). */
  matched: number;
  /** The path pattern matches every file (`**`, `*`), so the rule is suppressed everywhere. */
  wildcard: boolean;
  /** `expires` is more than a year ahead (`MAX_SUPPRESSION_HORIZON_DAYS`): flagged in the notices. */
  farExpiry: boolean;
}

/**
 * What `pgard.config.json` suppressed in this scan. Present whenever the config has at least one
 * entry; absent otherwise. Counts are always shown by every front end.
 */
export interface SuppressionSummary {
  source: SuppressionSource;
  /** Findings carrying `suppression`. */
  suppressed: number;
  /** Of those, how many are critical (a critical finding may be suppressed, never silently). */
  critical: number;
  /** Suppressed findings per severity (adds up to `suppressed`). */
  bySeverity: Record<Severity, number>;
  entries: SuppressionEntryResult[];
  /** True when the pattern work budget ran out: later findings were checked against no entry. */
  incomplete: boolean;
}

/** The baseline this result was compared with (`pgard baseline set`). Local state, not config. */
export interface BaselineSummary {
  /** When the baseline was set (ISO 8601). */
  setAt: string;
  scanId: string;
  revision: string | null;
  /** Findings in the baseline scan. */
  total: number;
  /**
   * Findings of this result that are in the baseline (flagged `inBaseline`) and not suppressed:
   * the size of the "In baseline" group. A suppressed finding is counted under `suppressions` only.
   */
  matched: number;
  /**
   * Findings of this result that are neither in the baseline nor suppressed. Includes test and
   * vendored findings, which the headline "New findings" count leaves out.
   */
  new: number;
  /** Of `new`, how many sit in areas the baseline did not fully cover (they may be old). */
  newInUncertainAreas: number;
  /** PGARD was updated since the baseline: rules may differ, so read the counts with care. */
  toolVersionChanged: boolean;
}

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
  /** Present when `pgard.config.json` has suppressions (JSON v1.1, optional). */
  suppressions?: SuppressionSummary;
  /** Present when a baseline was applied (JSON v1.1, optional). */
  baseline?: BaselineSummary;
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
