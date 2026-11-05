import type { CachedSourceFile } from "@pgard/findings";
import { analyzeFile, type FileToAnalyze } from "./analyze-file.js";
import { classifyAnalysisError, createJobRunner, type AnalysisError } from "./job-worker.js";

export { classifyAnalysisError, liveWorkerCount, MAX_WORKER_FAILURES } from "./job-worker.js";
export type { AnalysisError } from "./job-worker.js";

/**
 * Hard per-file limit for the JavaScript, TypeScript, Vue and Go analyzers.
 *
 * Their analysis is synchronous, so a file that makes it slow (a pathological regex, a quadratic
 * loop) used to hold the thread: neither the scan's time budget nor Ctrl+C could stop it. The scan
 * now sends each file to one worker thread and waits with a deadline. At the deadline, or when the
 * scan is aborted, the worker is terminated (safe here: it only runs CPU-bound code on a copy of
 * the text, no file handles or locks) and a fresh one serves the next file. The file is reported
 * as not analyzed and its area as partial, never as a clean result.
 *
 * A worker that cannot start, crashes, exits or answers with something malformed is a worker
 * failure: the file is reported as not analyzed for that reason. After MAX_WORKER_FAILURES of them
 * in a row no new worker is started and the remaining files get the same report; nothing falls
 * back to an unlimited analysis or to a completed result.
 *
 * One worker is kept per process between scans (unreferenced, so it never keeps the process
 * alive, and closed after a short idle time), so repeated scans do not pay its start-up again.
 * The runner itself is in `job-worker.ts`; the tree-sitter tracks use it too.
 */

/** Per-file limit when the scan does not set one. */
export const DEFAULT_PER_FILE_LIMIT_MS = 20_000;
/** The time budget may stop a file earlier, but never with less time than this. */
export const MIN_FILE_LIMIT_MS = 250;

export type FileOutcome =
  | { kind: "done"; entry: CachedSourceFile }
  | { kind: AnalysisError }
  /** The worker ran out of memory. */
  | { kind: "memory" }
  /** The per-file limit or the remaining time budget ran out; the analysis was stopped. */
  | { kind: "timeout" }
  /** The worker could not start, crashed, exited or sent a malformed answer. */
  | { kind: "worker" };

export interface WorkerRequest {
  id: number;
  file: FileToAnalyze;
  content: string;
  hash: string;
}

export type WorkerResponse =
  | { id: -1; kind: "ready" }
  | { id: number; kind: "done"; entry: CachedSourceFile }
  | { id: number; kind: AnalysisError };

const isStringList = (value: unknown) =>
  Array.isArray(value) && value.every((item) => typeof item === "string");

/** The shape the scan reads from an entry; anything else from a worker is a worker failure. */
export function isCachedSourceFile(value: unknown): value is CachedSourceFile {
  if (typeof value !== "object" || value === null) return false;
  const entry = value as Record<string, unknown>;
  return (
    typeof entry.path === "string" &&
    typeof entry.language === "string" &&
    typeof entry.hash === "string" &&
    Array.isArray(entry.findings) &&
    entry.findings.every((finding) => typeof finding === "object" && finding !== null) &&
    (entry.facts === null || (typeof entry.facts === "object" && !Array.isArray(entry.facts))) &&
    isStringList(entry.goImports) &&
    typeof entry.hasJsx === "boolean" &&
    typeof entry.hasParseErrors === "boolean" &&
    typeof entry.capped === "boolean"
  );
}

export interface FileAnalyzer {
  analyze(
    file: FileToAnalyze,
    content: string,
    hash: string,
    limitMs: number,
    signal: AbortSignal | undefined,
  ): Promise<FileOutcome>;
  /** Ends the scan's use of the analyzer (a worker goes back to the idle slot). */
  release(): void;
}

/**
 * The worker entry next to this module. Null when the code runs from its TypeScript source
 * (the test runner), where a worker could not load the `.ts` modules: analysis then runs in the
 * calling thread, without the hard limit. A built or packed scan always has the worker.
 */
export function defaultAnalysisWorker(): URL | null {
  if (import.meta.url.endsWith(".ts")) return null;
  return new URL("./analyze-worker.js", import.meta.url);
}

/** Runs the analysis in the calling thread (no hard limit; used when there is no worker). */
export function createInlineAnalyzer(): FileAnalyzer {
  return {
    analyze: async (file, content, hash) => {
      try {
        return { kind: "done", entry: analyzeFile(file, content, hash) };
      } catch (error) {
        return { kind: classifyAnalysisError(error) };
      }
    },
    release: () => {},
  };
}

/** Runs each file in a worker thread under a hard deadline (see the module comment). */
export function createWorkerAnalyzer(url: URL): FileAnalyzer {
  const runner = createJobRunner<Omit<WorkerRequest, "id">, CachedSourceFile>(
    url,
    "entry",
    isCachedSourceFile,
  );
  return {
    analyze: async (file, content, hash, limitMs, signal) => {
      const outcome = await runner.run({ file, content, hash }, limitMs, signal);
      return outcome.kind === "done" ? { kind: "done", entry: outcome.value } : outcome;
    },
    release: () => runner.release(),
  };
}
