/**
 * Worker entry for one file's analysis (`file-worker.ts` starts it). Analysis is synchronous and
 * CPU-bound, so the scan runs it here: the main thread stays free to stop it at the per-file time
 * limit (`worker.terminate()`) or on Ctrl+C, which it could not do while the analysis held it.
 */
import { parentPort } from "node:worker_threads";
import { analyzeFile } from "./analyze-file.js";
import { classifyAnalysisError, type WorkerRequest, type WorkerResponse } from "./file-worker.js";

if (parentPort === null) throw new Error("analyze-worker must run as a worker thread");
const port = parentPort;
port.on("message", (request: WorkerRequest) => {
  let response: WorkerResponse;
  try {
    response = {
      id: request.id,
      kind: "done",
      entry: analyzeFile(request.file, request.content, request.hash),
    };
  } catch (error) {
    response = { id: request.id, kind: classifyAnalysisError(error) };
  }
  port.postMessage(response);
});
port.postMessage({ id: -1, kind: "ready" } satisfies WorkerResponse);
