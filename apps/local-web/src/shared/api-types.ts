/**
 * JSON shapes exchanged between the local server and the browser. Browser-safe: types only.
 * Results are the redacted v1 ScanResult; no source code, tokens or absolute project paths.
 */
import type { AuthorizationSummary, RuleDetails, ScanResult, ScanScope } from "@pgard/findings";

export const SESSION_TOKEN_HEADER = "x-pgard-token";

export interface ApiError {
  error: { code: string; message: string };
}

export interface SessionInfo {
  version: string;
  /** `fixed`: `pgard dashboard` (one project, no picker). `picker`: `pgard web`. */
  mode: "fixed" | "picker";
  /**
   * PROTOTYPE (#414): `simple` is the one-screen code-only flow (`PGARD_WEB_PROTOTYPE=code-only`,
   * picker mode only); `full` is the current dashboard.
   */
  ui: "full" | "simple";
  /**
   * The selected project: its last path segment and `owner/name` only; the full path stays in the
   * terminal (fixed mode) or in the picker's confirm screen. `null` until one is confirmed.
   */
  project: ProjectInfo | null;
  /** Starts at 1 and grows on every confirm and clear; state-changing project calls carry it. */
  projectEpoch: number;
  /** Port pre-selected with `pgard dashboard --target-port`; still needs confirmation. */
  presetTargetPort: number | null;
  /**
   * The GitHub App the server signs in with: the built-in PGARD App, or the
   * `PGARD_GITHUB_APP_CLIENT_ID` override. The client id is public (device flow, no secret).
   */
  githubApp:
    | {
        clientId: string;
        /** Install-page slug; `null` when the client id is overridden without a slug. */
        slug: string | null;
        source: "default" | "env";
      }
    /**
     * An override (client id or slug) is set but malformed: identity is unverifiable and every
     * scan is blocked. `message` is fixed text naming the override, never its value.
     */
    | { clientId: null; slug: null; source: "invalid"; message: string };
  /**
   * Fixed warning when `PGARD_GITHUB_APP_SLUG` is overridden but the built-in client id is used
   * (the install link would point to another App); otherwise `null`.
   */
  githubAppWarning: string | null;
}

export interface ProjectInfo {
  name: string;
  /** `owner/name` of the remote; `null` in fixed mode (the check reports it). */
  repo: string | null;
}

export interface DeviceCodeInfo {
  userCode: string;
  verificationUri: string;
  expiresIn: number;
}

export type JobStatus = "idle" | "running" | "done" | "failed";

/**
 * Same shape as `OwnerApprovalRemedy` from `@pgard/policy` (the CLI shows the same data): owner
 * approval failed only because the PGARD GitHub App is not installed for this repository.
 * Guidance only; installing the App is the owner's approval and the full check runs again.
 */
export interface InstallRemedyDto {
  kind: "install_app";
  missing: "installation" | "repository" | "access" | "repository_access";
  account: { login: string; type: "User" | "Organization" };
  /**
   * Always an `https://github.com/...` URL, or `null` (see `unavailableReason`): the App's
   * install page (`/apps/...`), or for `repository_access` the existing installation's settings
   * page (`/settings/installations/<id>` or `/organizations/<org>/settings/installations/<id>`).
   */
  url: string | null;
  /**
   * `yes`: personal owner or active organization owner; `no`: GitHub shows they are not;
   * `unknown`: the organization membership could not be read yet (guided like `yes`).
   */
  canApprove: "yes" | "no" | "unknown";
  unavailableReason: string | null;
}

/** `POST /api/auth/owner-approval`: owner approval alone, checked again. Never an authorization. */
export interface OwnerApprovalRecheckDto {
  status: "passed" | "failed" | "unverifiable";
  reason: string;
  /** Still the install remedy while the App is missing; `null` once something changed. */
  remedy: InstallRemedyDto | null;
}

/**
 * The GitHub sign-in saved in the OS keychain, as the browser may see it: the account login at
 * most. The token itself stays in the local server process.
 */
export type StoredSignInDto =
  | { status: "stored"; login: string }
  | { status: "none" }
  | { status: "unavailable"; reason: string }
  /** Not read yet, or not readable because the client id override is invalid. */
  | { status: "unknown" };

export interface AuthStatus {
  /** An owner-approval re-check (waiting for an App install) is running. */
  isRechecking?: boolean;
  status: JobStatus;
  deviceCode: DeviceCodeInfo | null;
  summary: AuthorizationSummary | null;
  repo: string | null;
  message: string | null;
  storedSignIn: StoredSignInDto;
  /**
   * Set when the latest check is blocked only because the PGARD GitHub App is not installed for
   * this repository (`guidedInstallRemedy`); the panel offers the install link. `null` otherwise.
   */
  remedy: InstallRemedyDto | null;
  /**
   * Set when the latest check is blocked because GitHub showed no repository although the App is
   * installed on the owner account for all repositories. Not a remedy: adding the repository does
   * not apply, so the panel only explains. `null` otherwise.
   */
  accessNote: "app_covers_all_repositories" | null;
  /** Short, secret-free text about the sign-in (reused, saved, removed, signed out). */
  signInNotice: string | null;
  /**
   * Epoch ms after which an allowed check no longer opens port discovery and probes (the server
   * enforces it; this lets the panel say so). `null` unless the latest check is allowed.
   */
  expiresAt: number | null;
  /**
   * Epoch ms until which the server accepts owner-approval re-checks for the offered install
   * (10 minutes from when the check finished). Set only while the panel can wait for an install;
   * the server enforces it, so reloading or remounting the panel never extends the wait.
   */
  installWaitEndsAt: number | null;
}

export interface SignOutRequestDto {
  /** `true` also deletes the sign-in from the OS keychain; otherwise only this dashboard's session ends. */
  removeStored?: boolean;
}

export interface ServiceIdentityDto {
  port: number;
  url: string;
  status: number | null;
  title: string | null;
  inferredTechnologies: string[];
  isHttp: boolean;
  hasUnfollowedRedirect: boolean;
  error: string | null;
}

export interface PortListResponse {
  services: Array<ServiceIdentityDto & { processName: string | null }>;
  isDiscoveryAvailable: boolean;
  note: string | null;
}

export interface TargetInfo {
  port: number;
  origin: string;
  title: string | null;
}

export interface ScanProgressDto {
  stage: string;
  status: string;
  message: string;
}

export interface ScanStatus {
  status: JobStatus | "cancelled";
  scopes: ScanScope[];
  progress: ScanProgressDto[];
  result: ScanResult | null;
  message: string | null;
  /** Set while the GitHub sign-in started by this scan waits for the user. */
  deviceCode: DeviceCodeInfo | null;
  /**
   * PROTOTYPE (#414): true when this is a code-only scan (current files only, authorization not
   * checked). The page must label its result "not authorized".
   */
  codeOnly: boolean;
}

/** One rule's texts in each dashboard language. Same shape as `RuleTexts` in `@pgard/findings`. */
export interface RuleTextsDto {
  title: { en: string; ko: string };
  impact: { en: string; ko: string };
  recommendation: { en: string; ko: string };
  /** Standards links, examples and the rule-level texts (ids, titles and official URLs only). */
  details?: RuleDetails;
}

/** `GET /api/rule-texts`: rule id -> texts. Only the rule texts; no result data. */
export type RuleTextsResponse = Record<string, RuleTextsDto>;

/**
 * `GET /api/advisory-status`: whether the downloaded OSV data is present, how old it is and where
 * it is stored. Read from local files only; the dashboard never downloads advisory data.
 */
export interface AdvisoryStatusDto {
  /**
   * `none` when any ecosystem has no data (or there is no data folder); `unreadable` when the
   * status could not be read; otherwise `damaged`, `stale` or `fresh`.
   */
  overall: "none" | "fresh" | "stale" | "damaged" | "unreadable";
  /** Days after which data counts as stale (the same rule as `pgard doctor`). */
  staleAfterDays: number;
  /** Folder the data lives in (`<app data>/advisories/osv`); null without a home directory. */
  storePath: string | null;
  ecosystems: {
    ecosystem: string;
    state: "none" | "fresh" | "stale" | "damaged";
    fetchedAt: string | null;
    ageDays: number | null;
    modifiedMax: string | null;
    dataAgeDays: number | null;
    dataVersion: string | null;
  }[];
}

/** Formats the browser can download from `GET /api/reports/<format>`. */
export type ReportFormatDto = "html" | "pdf";

/** Most points a trend answer carries (the result store keeps at most this many scans per repository). */
export const TREND_MAX_POINTS = 20;

/** How completely one stored scan covered what it was asked to check. */
export type TrendCoverage = "completed" | "partial" | "not_tested";

/**
 * Findings of one stored scan by severity. Only active findings are counted here; suppressed
 * ("ignored") and baseline findings have their own counts, so the three never overlap.
 */
export interface TrendSeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/** What one scan changed against the scan before it (the M2-2 scan comparison). */
export interface TrendChangeDto {
  /** In this scan only. */
  new: number;
  /** In the earlier scan only, in a place fully analyzed both times ("no longer reported", not proof of a fix). */
  noLongerReported: number;
  unchanged: number;
  /** Earlier findings that could not be checked again (an area was not fully analyzed). */
  notComparable: number;
}

export interface TrendPointDto {
  /** When PGARD stored the scan (epoch ms). */
  savedAt: number;
  coverage: TrendCoverage;
  /** Coverage entries that were selected but not completed. */
  incompleteAreas: number;
  severity: TrendSeverityCounts;
  /** Active findings (the severity counts added up). */
  total: number;
  /** Findings ignored by `pgard.config.json` suppressions. */
  ignored: number;
  /** Findings that are in the saved baseline (and not ignored). */
  baselined: number;
  /** Against the point before this one; `null` for the first point or when the two do not compare. */
  change: TrendChangeDto | null;
}

/**
 * `GET /api/trend`: the saved CLI scans of the verified current repository, oldest first, counts
 * only. No paths, no finding text, no scan ids. At most `TREND_MAX_POINTS` points.
 */
export type TrendResponse =
  /** The result store is switched off (`--no-store` or `PGARD_NO_STORE=1`). */
  | { kind: "disabled" }
  | {
      kind: "unavailable";
      /** `not-verified`: no allowed authorization check yet, so scans cannot be matched to this repository. */
      why: "not-verified" | "no-store-dir" | "unreadable";
    }
  | {
      kind: "ready";
      points: TrendPointDto[];
      /** Stored files that could not be read. */
      skipped: number;
      /** Stored scans written by a newer PGARD, left out. */
      newerSkipped: number;
      /** Stored scans dated in the future, left out so they cannot reverse the order. */
      futureSkipped: number;
      /** Older stored files that were not opened because the cap was reached. */
      unread: number;
    };
