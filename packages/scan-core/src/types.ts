import type {
  AnalyzerOutput,
  CachedSourceFile,
  ConfirmedWebTarget,
  ProjectConfig,
  RuleMetadata,
} from "@pgard/findings";
import type { HistoryIncrementalBase, HistoryScanMode } from "@pgard/git-history";
import type { AuthorizationDependencies, AuthorizationOutcome } from "@pgard/policy";
import type { IncrementalDependencies } from "./incremental.js";

export interface WebScanProgress {
  pagesVisited: number;
  url: string;
}

export interface WebScanOptions {
  signal?: AbortSignal;
  onProgress?: (event: WebScanProgress) => void;
}

/**
 * Implemented by `@pgard/http-local` and injected by the launcher. scan-core never imports
 * http-local; it only calls this after authorization is `allowed` and with a user-confirmed
 * loopback target.
 */
export type WebScanner = (
  target: ConfirmedWebTarget,
  options: WebScanOptions,
) => Promise<AnalyzerOutput>;

export type ScanStage = "authorization" | "code" | "history" | "web";

export interface ScanProgressEvent {
  stage: ScanStage;
  status: "started" | "completed" | "failed" | "skipped";
  /** Short English message safe to display (no paths, tokens or secret values). */
  message: string;
  /** Present for `web` progress forwarded from the web scanner. */
  web?: WebScanProgress;
}

export interface AnalyzerContext {
  /** Absolute project root; analyzers must report repository-relative paths. */
  projectRoot: string;
  /**
   * The commit the authorization gate verified. Analyzers that read Git objects must scan this
   * revision rather than re-resolving HEAD, so the analyzed history cannot change after
   * authorization. (Source analysis reads the working tree, which is what the user runs.)
   */
  revision: string | null;
  signal?: AbortSignal;
  env: Readonly<Record<string, string | undefined>>;
  now: () => Date;
  /**
   * The validated `pgard.config.json`, or null when there is none or it was invalid (an invalid
   * file is ignored as a whole, never partly applied).
   */
  projectConfig: ProjectConfig | null;
  /**
   * Results of an earlier scan the code analyzer may reuse for files whose content did not
   * change (null or absent: analyze every file).
   */
  sourceReuse?: { files: ReadonlyMap<string, CachedSourceFile>; label: string } | null;
  /** What the history analyzer may carry over from an earlier scan (absent: scan all history). */
  historyIncremental?: HistoryIncrementalBase | null;
}

/**
 * What a local analyzer returns. The extra fields are optional: the built-in analyzers report
 * what they reused so the scan can say so, and an injected analyzer may leave them out.
 */
export type LocalAnalyzerOutput = AnalyzerOutput & {
  /** Per-file results for the next scan (code scope). */
  sourceCache?: CachedSourceFile[];
  /** Files analyzed now and files reused (code scope). */
  sourceReuse?: { rescanned: number; reused: number };
  /** How the history area was scanned (history scope). */
  history?: HistoryScanMode;
};

/** A local analyzer for one scope. Must be read-only and never execute project code. */
export type LocalAnalyzer = (context: AnalyzerContext) => Promise<LocalAnalyzerOutput>;

export interface ScanDependencies {
  /** Passed to `@pgard/policy` `authorizeProject`; the gate runs on every scan. */
  authorization: AuthorizationDependencies;
  webScanner?: WebScanner;
  /**
   * The rules the injected `webScanner` implements (`WEB_RULE_LIST` of `@pgard/http-local`).
   * scan-core never imports http-local, so the launcher passes them in; they only feed the
   * standards coverage map. Required whenever `webScanner` is set (`runScan` throws otherwise).
   */
  webRules?: ReadonlyArray<{ id: string; metadata: RuleMetadata }>;
  onProgress?: (event: ScanProgressEvent) => void;
  /**
   * Receives this scan's authorization outcome (allowed or blocked) right after the gate ran, so
   * a frontend can show `guidedInstallRemedy(outcome)`. Display only: the scan never reuses it,
   * and an error thrown here is ignored.
   */
  onAuthorization?: (outcome: AuthorizationOutcome) => void;
  /** Aborting rejects `runScan` with `ScanCancelledError`. */
  signal?: AbortSignal;
  /** Environment for analyzers. Defaults to `process.env`. */
  env?: Readonly<Record<string, string | undefined>>;
  now?: () => Date;
  createScanId?: () => string;
  /**
   * Incremental scans (JSON v1.2 `incremental`). Absent: every scan is a full one and the result
   * has no `incremental` field.
   */
  incremental?: IncrementalDependencies;
  /** Replaces built-in local analyzers (tests). Authorization still applies. */
  analyzers?: Partial<Record<"code" | "history", LocalAnalyzer>>;
}

export class ScanCancelledError extends Error {
  constructor() {
    super("The scan was cancelled.");
    this.name = "ScanCancelledError";
  }
}
