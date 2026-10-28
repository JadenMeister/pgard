import { getHeapStatistics } from "node:v8";
import { Worker } from "node:worker_threads";
import type { CachedSourceFile } from "@pgard/findings";
import { analyzeFile, type FileToAnalyze } from "./analyze-file.js";

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
 */

/** Per-file limit when the scan does not set one. */
export const DEFAULT_PER_FILE_LIMIT_MS = 20_000;
/** The time budget may stop a file earlier, but never with less time than this. */
export const MIN_FILE_LIMIT_MS = 250;
/** Consecutive worker failures after which no new worker is started for the scan. */
export const MAX_WORKER_FAILURES = 3;
/** Start-up limit for a fresh worker (it only loads the analyzers). */
const WORKER_START_LIMIT_MS = 30_000;
/** An idle worker is closed after this long. */
const IDLE_CLOSE_MS = 15_000;

/** An exception thrown by the analysis of one file. */
export type AnalysisError =
  /** The parser or analyzer recursed past the stack limit (deep nesting). */
  | "stack"
  /** Any other exception. */
  | "error";

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

export function classifyAnalysisError(error: unknown): AnalysisError {
  if (error instanceof RangeError && /call stack/i.test(error.message)) return "stack";
  return "error";
}

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

/**
 * Old-generation heap limit for a worker: the parent's own limit, kept between 512 MiB and
 * 2 GiB. A file needs far less (a 1 MiB TypeScript file takes a few hundred MiB at most); the cap
 * keeps a hostile file from taking the machine's memory, and running out is reported per file.
 */
function workerHeapLimitMb(): number {
  const parentMb = Math.floor(getHeapStatistics().heap_size_limit / (1024 * 1024));
  return Math.min(2048, Math.max(512, parentMb));
}

interface Slot {
  worker: Worker;
  ready: Promise<boolean>;
  idleTimer: ReturnType<typeof setTimeout> | null;
  alive: boolean;
}

/** Idle workers by entry URL, kept between scans. */
const idleSlots = new Map<string, Slot>();

/**
 * Starts a worker, or returns null when `new Worker` throws (a bad entry URL; on older Node
 * versions, process flags a worker refuses). The worker gets no process flags (`execArgv: []`):
 * flags such as `--max-old-space-size` or `--stack-size` make `new Worker` throw, and resolution
 * conditions (the test runner's `--conditions source`) would make it load TypeScript sources.
 */
function startSlot(url: URL): Slot | null {
  let worker: Worker;
  try {
    worker = new Worker(url, {
      execArgv: [],
      resourceLimits: { maxOldGenerationSizeMb: workerHeapLimitMb() },
    });
  } catch {
    return null;
  }
  const ready = new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => finish(false), WORKER_START_LIMIT_MS);
    const finish = (ok: boolean) => {
      clearTimeout(timer);
      worker.off("message", onMessage);
      worker.off("error", onFailure);
      worker.off("exit", onFailure);
      if (!ok) void worker.terminate();
      resolve(ok);
    };
    const onMessage = (message: unknown) => {
      if ((message as { kind?: unknown } | null)?.kind === "ready") finish(true);
      else finish(false);
    };
    const onFailure = () => finish(false);
    worker.on("message", onMessage);
    worker.once("error", onFailure);
    worker.once("exit", onFailure);
  });
  const slot: Slot = { worker, ready, idleTimer: null, alive: true };
  worker.once("exit", () => {
    slot.alive = false;
  });
  return slot;
}

function abortError(signal: AbortSignal): Error {
  return signal.reason instanceof Error ? signal.reason : new Error("aborted");
}

let liveWorkers = 0;

/** Workers started by this module that have not exited yet (tests: a stopped one must be gone). */
export function liveWorkerCount(): number {
  return liveWorkers;
}

function track(slot: Slot): void {
  liveWorkers += 1;
  slot.worker.once("exit", () => {
    liveWorkers -= 1;
  });
}

/** Runs each file in a worker thread under a hard deadline (see the module comment). */
export function createWorkerAnalyzer(url: URL): FileAnalyzer {
  const key = url.href;
  let slot: Slot | null = idleSlots.get(key) ?? null;
  idleSlots.delete(key);
  if (slot?.idleTimer) clearTimeout(slot.idleTimer);
  if (slot !== null && !slot.alive) slot = null;
  slot?.worker.ref();
  let nextId = 0;
  let failures = 0;

  const kill = () => {
    if (slot !== null) void slot.worker.terminate();
    slot = null;
  };
  /** A worker failure: the worker is gone, and the next file starts a new one (up to the cap). */
  const failed = (): FileOutcome => {
    kill();
    failures += 1;
    return { kind: "worker" };
  };

  const analyze = async (
    file: FileToAnalyze,
    content: string,
    hash: string,
    limitMs: number,
    signal: AbortSignal | undefined,
  ): Promise<FileOutcome> => {
    if (signal?.aborted) throw abortError(signal);
    if (failures >= MAX_WORKER_FAILURES) return { kind: "worker" };
    if (slot !== null && !slot.alive) slot = null;
    if (slot === null) {
      slot = startSlot(url);
      if (slot === null) return failed();
      track(slot);
    }
    const current = slot;
    // Start-up is not counted against the file; Ctrl+C still stops it.
    const started = await new Promise<boolean>((resolve, reject) => {
      const onAbort = () => {
        kill();
        reject(abortError(signal as AbortSignal));
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      void current.ready.then((ok) => {
        signal?.removeEventListener("abort", onAbort);
        resolve(ok);
      });
    });
    if (!started || !current.alive) return failed();
    const id = (nextId += 1);
    const outcome = await new Promise<FileOutcome | "failed">((resolve, reject) => {
      const { worker } = current;
      const timer = setTimeout(() => {
        cleanup();
        kill();
        resolve({ kind: "timeout" });
      }, limitMs);
      const onAbort = () => {
        cleanup();
        kill();
        reject(abortError(signal as AbortSignal));
      };
      const onMessage = (message: unknown) => {
        const reply = message as { id?: unknown; kind?: unknown; entry?: unknown } | null;
        if (reply?.id !== id) return;
        cleanup();
        if (reply.kind === "done" && isCachedSourceFile(reply.entry)) {
          resolve({ kind: "done", entry: reply.entry });
        } else if (reply.kind === "stack" || reply.kind === "error") {
          resolve({ kind: reply.kind });
        } else {
          resolve("failed");
        }
      };
      const onError = (error: Error & { code?: string }) => {
        cleanup();
        if (error.code === "ERR_WORKER_OUT_OF_MEMORY") {
          kill();
          resolve({ kind: "memory" });
        } else {
          resolve("failed");
        }
      };
      const onExit = () => {
        cleanup();
        resolve("failed");
      };
      const cleanup = () => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        worker.off("message", onMessage);
        worker.off("error", onError);
        worker.off("exit", onExit);
      };
      signal?.addEventListener("abort", onAbort, { once: true });
      worker.on("message", onMessage);
      worker.on("error", onError);
      worker.on("exit", onExit);
      try {
        worker.postMessage({ id, file, content, hash } satisfies WorkerRequest);
      } catch {
        cleanup();
        resolve("failed");
      }
    });
    if (outcome === "failed") return failed();
    if (outcome.kind !== "memory") failures = 0;
    return outcome;
  };

  const release = () => {
    const kept = slot;
    slot = null;
    if (kept === null) return;
    if (idleSlots.has(key) || !kept.alive) {
      void kept.worker.terminate();
      return;
    }
    kept.worker.unref();
    kept.idleTimer = setTimeout(() => {
      if (idleSlots.get(key) === kept) idleSlots.delete(key);
      void kept.worker.terminate();
    }, IDLE_CLOSE_MS);
    kept.idleTimer.unref();
    idleSlots.set(key, kept);
  };

  return { analyze, release };
}
