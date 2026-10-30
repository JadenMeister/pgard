/**
 * PGARD common result contract (JSON v1).
 *
 * Every frontend (CLI, local web, reports) renders exactly this shape. Analyzers return
 * `AnalyzerOutput`; `scan-core` assembles a `ScanResult`. Anything that was not run is
 * recorded in `coverage`, never as "safe".
 */

export const SCHEMA_VERSION = "1.7" as const;

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
  /**
   * Only on `source:build-output` (JSON v1.3). The skip-named directories (`build`, `dist`, ...)
   * that the walk entered because they directly contain source files, as redacted
   * repository-relative paths; `complete` is false when the walk stopped early and the list may
   * be missing some. Comparison uses it to treat findings below them as ordinary. Absent: not
   * recorded (a result older than 1.3), which a reader must treat as "unknown".
   */
  walkedDirectories?: { paths: string[]; complete: boolean };
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
  /**
   * JSON v1.4. SEI CERT Oracle Java rule ids (`IDS00-J`) that the finding's rule is directly about.
   * Present only on findings in Java or Kotlin files whose rule has such a mapping; absent
   * everywhere else (other languages link to CERT only indirectly, through a CWE, in the rule
   * details). A reference is not a compliance claim.
   */
  cert?: string[];
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
  /**
   * JSON v1.5. Only on `PG-DEP-001` findings: which package version matched which advisory. It
   * records a version-range match, not exploitability or reachability.
   */
  dependency?: FindingDependency;
  /**
   * JSON v1.6. Only on findings of a rule that declares `fixable` (see `RuleDescriptor.fixable`):
   * a suggested fix to review. PGARD never applies it and never writes to the scanned files.
   */
  fix?: FindingFix;
}

/**
 * - `diff`: a unified diff of the scanned file (see `FindingFix.diff`).
 * - `guidance`: the rule can offer a diff, but not for this finding; the rule's recommendation is
 *   the advice. `reason` says why there is no diff.
 */
export type FindingFixKind = "diff" | "guidance";
export const FINDING_FIX_KINDS = exhaustive<FindingFixKind>({ diff: true, guidance: true });

/**
 * A suggestion, not a verified change: it is not checked to compile, to keep behaviour or to be
 * complete, and a person must review it. It is built from the analyzed source text alone; the
 * scanned code is never run.
 */
export interface FindingFix {
  kind: FindingFixKind;
  /**
   * `kind: "diff"` only. A unified diff of one repository file with a single hunk, no context lines
   * (apply it with `git apply --unidiff-zero`), at most `MAX_FIX_DIFF_LENGTH` characters. Every line
   * went through secret redaction; a line that redaction would change is never put in a diff.
   */
  diff?: string;
  /** How sure PGARD is that the rewrite keeps the meaning of the flagged code. Not a safety claim. */
  confidence: Confidence;
  /**
   * `kind: "guidance"` only, an open-ended code: `context_not_supported` (the code around the
   * finding is not one of the rewrites the rule offers), `sensitive_text` (the line holds text
   * that redaction would change), `too_large`, `source_unavailable`, `too_many`.
   */
  reason?: string;
}

/** Upper bound for `FindingFix.diff`. */
export const MAX_FIX_DIFF_LENGTH = 2_000;

/** How a dependency finding's severity was decided: a computed CVSS score, a label, or neither. */
export type DependencySeveritySource = "cvss" | "database" | "unknown";
export const DEPENDENCY_SEVERITY_SOURCES = exhaustive<DependencySeveritySource>({
  cvss: true,
  database: true,
  unknown: true,
});

export interface FindingDependency {
  /** OSV ecosystem name (`npm`, `Go`). */
  ecosystem: string;
  name: string;
  /** The version the lockfile pins. */
  version: string;
  /** True when the lockfile says the package is needed only for development. Absent: not stated. */
  dev?: boolean;
  /** Absent: the lockfile does not say whether the package is a direct dependency. */
  direct?: boolean;
  /** Primary advisory id (GHSA, GO, ...). Part of the fingerprint. */
  advisoryId: string;
  /** Other ids of the same issue (CVE, GHSA, GO, ...). */
  aliases: string[];
  /** The affected range the version is in, e.g. `>=1.0.0 <1.2.3`, or `all versions`. */
  affectedRange: string;
  /** Fixed versions newer than the installed one; empty when none is published. */
  fixedVersions: string[];
  /**
   * `cvss`: the level comes from the CVSS v3 base score computed from `vector`. `database`: from
   * the advisory database's own label. `unknown`: neither exists and the finding is `medium`.
   */
  severitySource: DependencySeveritySource;
  /** CVSS base score (0-10), when `severitySource` is `cvss`. */
  score?: number;
  /** The CVSS vector as published, when the advisory has one. */
  vector?: string;
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
 * Kept in JSON v1 for compatibility only. PGARD ships no vulnerability database (OSV data is
 * user-downloaded and matched locally), so both fields are always `null`.
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

/**
 * Why a scan (or one of its areas) was a full scan instead of an incremental one. Stable codes:
 * frontends translate them.
 *
 * - `requested_full`: the user asked for a full scan (`--full`).
 * - `no_previous_scan`: nothing is stored for this repository (first scan, or stored results are off).
 * - `store_unavailable`: the result store could not be read.
 * - `previous_unreadable`: the newest stored scan is corrupt, expired or from an incompatible PGARD.
 * - `no_saved_state`: the stored scan has no incremental data (older PGARD, or too large to keep).
 * - `scopes_changed`: the stored scan covered other scopes than this one.
 * - `tool_changed`: the PGARD version, rule metadata, advisory data or grammar hashes changed.
 * - `config_changed`: `pgard.config.json` changed (or appeared or disappeared).
 * - `previous_incomplete`: a stored area was partial or not tested.
 * - `head_not_ancestor`: the stored commit is not an ancestor of HEAD (rebase, force-push, other clone).
 * - `git_failed`: Git could not list the changes since the stored commit.
 * - `rules_unclassified`: a rule is not classified as file-local or project-wide.
 * - `analyzer_changed`: the analyzer code that decides findings changed since the stored scan.
 * - `previous_state_too_large`: the stored scan's reuse data was too large to keep.
 * - `previous_state_rejected`: the stored scan's reuse data was dropped or failed its checks.
 * - `history_changed`: the new commits change what the earlier history findings mean, so the
 *   Git history was scanned in full (the code area may still be incremental).
 */
export type IncrementalFullReason =
  | "requested_full"
  | "no_previous_scan"
  | "store_unavailable"
  | "previous_unreadable"
  | "no_saved_state"
  | "scopes_changed"
  | "tool_changed"
  | "config_changed"
  | "previous_incomplete"
  | "head_not_ancestor"
  | "git_failed"
  | "rules_unclassified"
  | "analyzer_changed"
  | "previous_state_too_large"
  | "previous_state_rejected"
  | "history_changed";
export const INCREMENTAL_FULL_REASONS = exhaustive<IncrementalFullReason>({
  requested_full: true,
  no_previous_scan: true,
  store_unavailable: true,
  previous_unreadable: true,
  no_saved_state: true,
  scopes_changed: true,
  tool_changed: true,
  config_changed: true,
  previous_incomplete: true,
  head_not_ancestor: true,
  git_failed: true,
  rules_unclassified: true,
  analyzer_changed: true,
  previous_state_too_large: true,
  previous_state_rejected: true,
  history_changed: true,
});

/** How one local area was scanned. */
export interface IncrementalAreaInfo {
  mode: "incremental" | "full";
  /** Why it was a full scan; null when `mode` is `incremental`. */
  reason: IncrementalFullReason | null;
}

/**
 * Added in 1.2, present when the launcher offered incremental scans. Says what the scan reused
 * from an earlier stored scan: nothing is reused silently.
 */
export interface IncrementalInfo {
  /** True when at least one area reused data from the stored scan. */
  used: boolean;
  /** Why the scan was a full one (the code area's reason when both areas were full); else null. */
  reason: IncrementalFullReason | null;
  /** The stored scan this one is based on; null for a full scan. */
  basedOn: { scanId: string; revision: string | null } | null;
  /** Source files analyzed in this scan (all of them in a full scan). Null: no code scope. */
  filesRescanned: number | null;
  /** Source files whose stored findings were reused because their content did not change. */
  filesReused: number | null;
  /** Commits scanned in this scan (for an incremental one: only the new commits). Null: no history scope. */
  commitsScanned: number | null;
  /** Commits whose earlier history findings were carried over. */
  commitsReused: number | null;
  code: IncrementalAreaInfo | null;
  history: IncrementalAreaInfo | null;
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
  /** Added in 1.2. Absent in older results and when the launcher did not offer incremental scans. */
  incremental?: IncrementalInfo;
  /**
   * Added in 1.7: whether the authorization gate ran and passed. Absent in older results, and a
   * reader treats absent as `mode: "authorized"` with the gate's own `authorization.decision`
   * (older PGARD ran the gate before every scan).
   */
  scanBasis?: ScanBasis;
}

/**
 * - `authorized`: the authorization gate ran (`authorization` holds its five checks).
 * - `code_only`: no gate ran. Only the current files were analyzed; no Git history, no web
 *   checks, nothing stored. Authorization was not proven.
 */
export type ScanBasisMode = "authorized" | "code_only";
export const SCAN_BASIS_MODES = exhaustive<ScanBasisMode>({ authorized: true, code_only: true });

/** `verified` only when the gate ran and allowed the scan. */
export type ScanBasisAuthorization = "verified" | "not_verified";
export const SCAN_BASIS_AUTHORIZATIONS = exhaustive<ScanBasisAuthorization>({
  verified: true,
  not_verified: true,
});

/**
 * Why authorization is `not_verified`: an open-ended code (a reader shows an unknown one as is).
 * Known codes: `no_approval` (the gate ran and did not allow the scan), `check_failed` (the
 * gate could not reach a decision: no GitHub sign-in, a network error or time-out, or an
 * internal error), `not_checked` (a code-only scan that did not try the gate),
 * `no_github_remote` (a Git repository without a single github.com remote),
 * `not_a_git_repository` (also a repository with no commit yet: there is no revision to
 * authorize), `offline`.
 */
export const SCAN_BASIS_REASONS = [
  "no_approval",
  "check_failed",
  "not_checked",
  "no_github_remote",
  "not_a_git_repository",
  "offline",
] as const;
export type KnownScanBasisReason = (typeof SCAN_BASIS_REASONS)[number];

/** Added in 1.7. */
export interface ScanBasis {
  mode: ScanBasisMode;
  authorization: ScanBasisAuthorization;
  /** `null` exactly when `authorization` is `verified`. Lowercase letters and `_`, at most 64. */
  reason: string | null;
}

/** True for a result written by a code-only scan (1.7 and later). */
export function isCodeOnlyResult(result: Pick<ScanResult, "scanBasis">): boolean {
  return result.scanBasis?.mode === "code_only";
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
  /**
   * The repository the user confirmed before the scan (the `pgard web` picker). When set, the
   * authorization gate blocks the scan unless the project resolves to exactly this repository.
   * It can only block; it never relaxes a check.
   */
  expectedRepo?: { owner: string; name: string; repositoryId?: number | null } | null;
}
