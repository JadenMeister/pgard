/**
 * Worker entry for the tree-sitter tracks (`tree-sitter/track-jobs.ts` starts it). A job is one
 * file's parse and rule analysis, or the text analysis of a mapper, template or configuration
 * file. The scan runs it here so the main thread can stop it at the per-file limit
 * (`worker.terminate()`) or on Ctrl+C, which it could not do while the analysis held the thread.
 *
 * The worker loads the WASM grammars itself through `TreeSitterRuntime`, which reads each grammar
 * and verifies its pinned SHA-256 before loading the verified bytes: the check is the same as in
 * the main thread and cannot be skipped. A grammar that fails it is reported as `unavailable`.
 * The runtime is kept between jobs, so a grammar loads once per worker.
 */
import { parentPort } from "node:worker_threads";
import { classifyAnalysisError } from "./job-worker.js";
import { runTrackJob, type TrackJob } from "./tree-sitter/track-jobs.js";
import { TreeSitterRuntime } from "./tree-sitter/runtime.js";

if (parentPort === null) throw new Error("track-worker must run as a worker thread");
const port = parentPort;
const runtime = new TreeSitterRuntime();
port.on("message", (request: { id: number; job: TrackJob }) => {
  void (async () => {
    try {
      const result = await runTrackJob(request.job, runtime);
      port.postMessage({ id: request.id, kind: "done", result });
    } catch (error) {
      port.postMessage({ id: request.id, kind: classifyAnalysisError(error) });
    }
  })();
});
port.postMessage({ id: -1, kind: "ready" });
