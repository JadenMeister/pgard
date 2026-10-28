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
 * One worker is kept per process between scans (unreferenced, so it never keeps the process
 * alive, and closed after a short idle time), so repeated scans do not pay its start-up again.
 */

/** Per-file limit when the scan does not set one. */
export const DEFAULT_PER_FILE_LIMIT_MS = 20_000;
/** The time budget may stop a file earlier, but never with less time than this. */
export const MIN_FILE_LIMIT_MS = 250;
/** Start-up limit for a fresh worker (it only loads the analyzers). */
const WORKER_START_LIMIT_MS = 30_000;
/** An idle worker is closed after this long. */
const IDLE_CLOSE_MS = 15_000;

/** Why a file has no result. */
export type AnalysisFailure =
  /** The parser or analyzer recursed past the stack limit (deep nesting). */
  | "stack"
  /** The worker ran out of memory. */
  | "memory"
  /** Any other exception. */
  | "error";

export type FileOutcome =
  | { kind: "done"; entry: CachedSourceFile }
  | { kind: AnalysisFailure }
  /** The per-file limit or the remaining time budget ran out; the analysis was stopped. */
  | { kind: "timeout" };

export interface WorkerRequest {
  id: number;
  file: FileToAnalyze;
  content: string;
  hash: string;
}

export type WorkerResponse =
  | { id: -1; kind: "ready" }
  | { id: number; kind: "done"; entry: CachedSourceFile }
  | { id: number; kind: AnalysisFailure };

export function classifyAnalysisError(error: unknown): AnalysisFailure {
  if (error instanceof RangeError && /call stack/i.test(error.message)) return "stack";
  return "error";
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

interface Slot {
  worker: Worker;
  ready: Promise<boolean>;
  idleTimer: ReturnType<typeof setTimeout> | null;
  alive: boolean;
}

/** Idle workers by entry URL, kept between scans. */
const idleSlots = new Map<string, Slot>();

/**
 * The process flags for the worker, without module resolution conditions: the worker loads the
 * built modules it sits next to, also when the parent resolves workspace packages to their
 * TypeScript source (the test runner adds `--conditions source`).
 */
function workerExecArgv(): string[] {
  const out: string[] = [];
  const args = process.execArgv;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] as string;
    if (arg === "--conditions" || arg === "-C") index += 1;
    else if (!arg.startsWith("--conditions=") && !arg.startsWith("-C=")) out.push(arg);
  }
  return out;
}

function startSlot(url: URL): Slot {
  const worker = new Worker(url, { execArgv: workerExecArgv() });
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
    const onMessage = (message: WorkerResponse) => {
      if (message.kind === "ready") finish(true);
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

/** Runs each file in a worker thread under a hard deadline (see the module comment). */
export function createWorkerAnalyzer(url: URL): FileAnalyzer {
  const key = url.href;
  let slot: Slot | null = idleSlots.get(key) ?? null;
  idleSlots.delete(key);
  if (slot?.idleTimer) clearTimeout(slot.idleTimer);
  if (slot !== null && !slot.alive) slot = null;
  slot?.worker.ref();
  let nextId = 0;

  const kill = () => {
    if (slot !== null) void slot.worker.terminate();
    slot = null;
  };

  const analyze = async (
    file: FileToAnalyze,
    content: string,
    hash: string,
    limitMs: number,
    signal: AbortSignal | undefined,
  ): Promise<FileOutcome> => {
    if (signal?.aborted) throw abortError(signal);
    if (slot !== null && !slot.alive) slot = null;
    if (slot === null) slot = startSlot(url);
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
    if (!started) {
      if (slot === current) slot = null;
      return { kind: "error" };
    }
    const id = (nextId += 1);
    return new Promise<FileOutcome>((resolve, reject) => {
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
      const onMessage = (message: WorkerResponse) => {
        if (message.id !== id) return;
        cleanup();
        resolve(
          message.kind === "done"
            ? { kind: "done", entry: message.entry }
            : { kind: message.kind as AnalysisFailure },
        );
      };
      const onError = (error: Error & { code?: string }) => {
        cleanup();
        kill();
        resolve({ kind: error.code === "ERR_WORKER_OUT_OF_MEMORY" ? "memory" : "error" });
      };
      const onExit = () => {
        cleanup();
        if (slot === current) slot = null;
        resolve({ kind: "error" });
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
      worker.postMessage({ id, file, content, hash } satisfies WorkerRequest);
    });
  };

  const release = () => {
    const kept = slot;
    slot = null;
    if (kept === null) return;
    if (idleSlots.has(key)) {
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
