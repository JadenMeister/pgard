#!/usr/bin/env node
import { fileURLToPath } from "node:url";
import { startLocalWebServer } from "./create-server.js";
import { LauncherUsageError, parseLauncherArgs } from "./launcher.js";
import { loadStaticAssets } from "./static-files.js";

/**
 * Dashboard process entry, started by `pgard dashboard` with this Node binary. Prints the
 * private session URL (token in the URL fragment, so it is not sent in requests or Referer headers).
 */
async function runLauncher(): Promise<number> {
  let options;
  try {
    options = await parseLauncherArgs(process.argv.slice(2));
  } catch (error) {
    process.stderr.write(
      `${error instanceof LauncherUsageError ? error.message : "Invalid arguments."}\n`,
    );
    return 2;
  }
  const clientDir = fileURLToPath(new URL("../client/", import.meta.url));
  const assets = await loadStaticAssets(clientDir);
  if (!assets.has("/")) {
    process.stderr.write("The dashboard UI is not built (run npm run build).\n");
    return 5;
  }
  const server = await startLocalWebServer({
    projectRoot: options.projectRoot,
    presetTargetPort: options.presetTargetPort,
    env: process.env,
    assets,
  });
  process.stdout.write(
    [
      "PGARD dashboard is running on 127.0.0.1 only.",
      `Open this private session URL in your browser (valid until you stop the dashboard): ${server.url}`,
      "Do not share this URL. Press Ctrl+C to stop; results and sign-in are discarded on exit.",
      "",
    ].join("\n"),
  );
  return new Promise<number>((resolve) => {
    let isStopping = false;
    const stop = (): void => {
      if (isStopping) return;
      isStopping = true;
      process.stdout.write("Stopping dashboard; discarding session state.\n");
      void server.close().then(() => resolve(0));
    };
    // `on`, not `once`: Ctrl+C can arrive twice (terminal process group + the CLI forwarding
    // it); a second signal must not kill the process before state is discarded.
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
  });
}

process.exitCode = await runLauncher();
