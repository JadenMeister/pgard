import { performance } from "node:perf_hooks";
import { runGit } from "@pgard/git-history";
import { inspectRepository } from "@pgard/policy";
import { nodeScopeFs } from "@pgard/result-store";
import { runInspectorJob } from "./inspect.js";
import type { ChildMessage, InspectorJob } from "./protocol.js";

/**
 * Entry of the inspector child process (see `inspector-host.ts`). It receives exactly one job
 * over the IPC channel, reports back as JSON messages the server validates, and exits. It has no
 * stdout or stderr, no token and no path on its command line.
 */

// Windows is not supported by the picker; a stray start there does nothing useful.
if (process.send === undefined) process.exit(2);

// The server went away (or closed the channel): there is nobody to report to.
process.on("disconnect", () => process.exit(0));

function send(message: ChildMessage): Promise<void> {
  return new Promise((resolve) => {
    if (process.send === undefined || !process.connected) return resolve();
    process.send(message, undefined, undefined, () => resolve());
  });
}

process.once("message", (raw: unknown) => {
  const job = raw as InspectorJob;
  const pending: Array<Promise<void>> = [];
  void runInspectorJob(
    {
      fs: nodeScopeFs,
      uid: process.getuid?.(),
      runGit,
      inspectRepository,
      now: () => performance.now(),
      platform: process.platform,
      emit: (message) => {
        pending.push(send(message));
      },
    },
    job,
  )
    .then(() => Promise.all(pending))
    .then(() => process.exit(0))
    .catch(() => process.exit(1));
});
