import type { AdvisoryDbInfo, AnalyzerOutput, ConfirmedWebTarget } from "@pgard/findings";
import type { AuthorizationDependencies } from "@pgard/policy";

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
}

/** `code` analyzers also report which advisory database they compared against. */
export interface LocalAnalyzerOutput extends AnalyzerOutput {
  advisoryDb?: AdvisoryDbInfo;
}

/** A local analyzer for one scope. Must be read-only and never execute project code. */
export type LocalAnalyzer = (context: AnalyzerContext) => Promise<LocalAnalyzerOutput>;

export interface ScanDependencies {
  /** Passed to `@pgard/policy` `authorizeProject`; the gate runs on every scan. */
  authorization: AuthorizationDependencies;
  webScanner?: WebScanner;
  onProgress?: (event: ScanProgressEvent) => void;
  /** Aborting rejects `runScan` with `ScanCancelledError`. */
  signal?: AbortSignal;
  /** Environment for analyzers (e.g. `PGARD_ADVISORY_DB`). Defaults to `process.env`. */
  env?: Readonly<Record<string, string | undefined>>;
  now?: () => Date;
  createScanId?: () => string;
  /** Replaces built-in local analyzers (tests). Authorization still applies. */
  analyzers?: Partial<Record<"code" | "history", LocalAnalyzer>>;
}

export class ScanCancelledError extends Error {
  constructor() {
    super("The scan was cancelled.");
    this.name = "ScanCancelledError";
  }
}
