#!/usr/bin/env node
import { fileURLToPath } from "node:url";
import {
  createWebStorage,
  loadSearchScope,
  resolveStoreDirectory,
  type WebStorage,
} from "@pgard/result-store";
import { sanitizeDisplayText } from "@pgard/http-local";
import { openGitHubUrl } from "@pgard/scan-core";
import { createDefaultServerDeps, startLocalWebServer, type ServerDeps } from "./create-server.js";
import { LauncherUsageError, parseLauncherArgs, type LauncherOptions } from "./launcher.js";
import { createInspectorHost } from "./picker/inspector-host.js";
import { loadStaticAssets } from "./static-files.js";

// Defence in depth on Windows: never search the current directory for executables.
process.env.NoDefaultCurrentDirectoryInExePath = "1";

/**
 * Picker mode (`pgard web`): the search folders and the recent list. The folders were shown and
 * confirmed in the terminal by `pgard web` before this process started; they are revalidated
 * here (a folder that is no longer safe is dropped and reported), never taken from the browser.
 */
async function createPickerDeps(
  options: LauncherOptions,
): Promise<NonNullable<ServerDeps["picker"]>> {
  const homeDir = process.env.HOME ?? process.env.USERPROFILE ?? "";
  const dataDir = resolveStoreDirectory({ env: process.env, homeDir });
  const storage: WebStorage | null =
    options.noStore || dataDir === null ? null : createWebStorage({ dir: dataDir });
  const scope = await loadSearchScope({ storage, uid: process.getuid?.(), homeDir });
  for (const dropped of scope.dropped) {
    process.stdout.write(
      `Search folder skipped (${dropped.reason}): ${sanitizeDisplayText(dropped.path, 500)}\n`,
    );
  }
  process.stdout.write(
    scope.roots.length === 0
      ? "No search folders are usable. Add one with: pgard web scope add <folder>\n"
      : `Search folders: ${scope.roots.map((root) => sanitizeDisplayText(root.path, 500)).join(", ")}\n`,
  );
  return {
    inspector: createInspectorHost(),
    storage,
    roots: scope.roots,
    homeDir,
    platform: process.platform,
  };
}

/**
 * Dashboard process entry, started by `pgard dashboard` or `pgard web` with this Node binary.
 * Prints the private session URL (token in the URL fragment, so it is not sent in requests or
 * Referer headers).
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
  if (options.picker && process.platform === "win32") {
    process.stderr.write(
      "The project picker is not available on Windows yet. Use `pgard dashboard` in the project folder.\n",
    );
    return 2;
  }
  const clientDir = fileURLToPath(new URL("../client/", import.meta.url));
  const assets = await loadStaticAssets(clientDir);
  if (!assets.has("/")) {
    process.stderr.write("The dashboard UI is not built (run npm run build).\n");
    return 5;
  }
  const deps = options.picker
    ? { ...createDefaultServerDeps(), picker: await createPickerDeps(options) }
    : undefined;
  const server = await startLocalWebServer({
    projectRoot: options.projectRoot,
    presetTargetPort: options.presetTargetPort,
    env: process.env,
    assets,
    ...(deps === undefined ? {} : { deps }),
    // Like the CLI: open the GitHub sign-in page automatically only for a person at a terminal
    // who did not pass --no-browser. The page is also linked in the dashboard.
    ...(options.noBrowser || process.stdout.isTTY !== true
      ? {}
      : { openGitHubPage: (url: string) => void openGitHubUrl(url) }),
  });
  process.stdout.write(
    [
      options.picker
        ? "PGARD web (project picker) is running on 127.0.0.1 only."
        : "PGARD dashboard is running on 127.0.0.1 only.",
      `Open this private session URL in your browser (valid until you stop the dashboard): ${server.url}`,
      "Do not share this URL. Press Ctrl+C to stop; dashboard results and the session are discarded on exit.",
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
