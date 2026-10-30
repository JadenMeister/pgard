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
import { announceLaunch, connectedLine } from "./launch-output.js";
import { LauncherUsageError, parseLauncherArgs, type LauncherOptions } from "./launcher.js";
import { createFolderDialog } from "./picker/folder-dialog.js";
import { createInspectorHost } from "./picker/inspector-host.js";
import { loadStaticAssets } from "./static-files.js";

// Defence in depth on Windows: never search the current directory for executables.
process.env.NoDefaultCurrentDirectoryInExePath = "1";

/**
 * Picker mode (`pgard web`): the folder dialog, the folder checks and the recent list. The simple
 * screen needs no setup: the folder is chosen in the browser and checked here. Saved search
 * folders (`pgard web scope add`) are revalidated for the search picker under "More" (a folder
 * that is no longer safe is dropped and reported), never taken from the browser.
 */
async function createPickerDeps(
  options: LauncherOptions,
): Promise<NonNullable<ServerDeps["picker"]>> {
  const homeDir = process.env.HOME ?? process.env.USERPROFILE ?? "";
  const dataDir = resolveStoreDirectory({ env: process.env, homeDir });
  const storage: WebStorage | null =
    options.noStore || dataDir === null ? null : createWebStorage({ dir: dataDir });
  const scope = await loadSearchScope({ storage, uid: process.getuid?.(), homeDir });
  for (const dropped of scope.source === "stored" ? scope.dropped : []) {
    process.stdout.write(
      `Search folder skipped (${dropped.reason}): ${sanitizeDisplayText(dropped.path, 500)}\n`,
    );
  }
  return {
    inspector: createInspectorHost(),
    // The simple screen's "Choose folder" button (none on Windows: paste the path instead).
    folderDialog: createFolderDialog(),
    storage,
    // The search picker ("More" > full dashboard) searches only folders saved with
    // `pgard web scope add`; the default development folders are never searched unconfirmed.
    roots: scope.source === "stored" ? scope.roots : [],
    homeDir,
    platform: process.platform,
  };
}

/**
 * Dashboard process entry, started by `pgard dashboard` or `pgard web` with this Node binary.
 * Opens the one-time session link in the browser and prints it masked (#419); the token is in
 * the URL fragment, so it is never sent in requests or Referer headers.
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
    ? {
        ...createDefaultServerDeps(),
        picker: await createPickerDeps(options),
        isStoreDisabled: options.noStore,
      }
    : undefined;
  const server = await startLocalWebServer({
    projectRoot: options.projectRoot,
    presetTargetPort: options.presetTargetPort,
    env: process.env,
    assets,
    ...(deps === undefined ? {} : { deps }),
    onBrowserConnected: (at) => process.stdout.write(connectedLine(at)),
    // Like the CLI: open the GitHub sign-in page automatically only for a person at a terminal
    // who did not pass --no-browser. The page is also linked in the dashboard.
    ...(options.noBrowser || process.stdout.isTTY !== true
      ? {}
      : { openGitHubPage: (url: string) => void openGitHubUrl(url) }),
  });
  // Opens the local page for a person at a terminal (#419). The terminal then shows the link
  // with its one-time token masked; the full link only when the browser was not opened, or with
  // --print-url. The link is never written to a log file.
  await announceLaunch({
    url: server.url,
    mode: options.picker ? "picker" : "fixed",
    printUrl: options.printUrl,
    environment: {
      platform: process.platform,
      env: process.env,
      isTerminal: process.stdout.isTTY === true,
      isDisabled: options.noOpen || options.noBrowser,
    },
    write: (text) => process.stdout.write(text),
  });
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
