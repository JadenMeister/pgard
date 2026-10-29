// Dev-only preview of the PROTOTYPE one-screen code-only flow (#414). Not part of the package
// (`files` is `dist` only) and never started by pgard. It runs the REAL dashboard server in picker
// mode with the simple screen, the REAL OS folder dialog, the REAL inspector child process
// (realpath, ownership and write-bit checks) and the REAL code-only scan of the folder you choose.
//
// Read-only and offline:
// - no GitHub: the keychain is replaced by an in-memory store (the native keychain binding is
//   never loaded), the GitHub sign-in always fails, and verify, authorized scans, owner approval
//   and local web checks throw if anything ever reached them;
// - no network: local port discovery and probing are disabled, the code-only scan reads files;
// - nothing stored and nothing read from PGARD's data folder (~/Library/Application Support/pgard
//   on macOS): no result store, no recent list, no settings, no advisory (OSV) data, so
//   dependency checks report "not tested".
//
//   npm run build
//   node apps/local-web/dev/code-only-preview-server.mjs <home-folder> [port]   (never 4317/4318)
//   open the printed http://127.0.0.1:<port>/#token=... URL
import { createInMemoryCredentialStore } from "@pgard/scan-core";
import { createDefaultServerDeps, startLocalWebServer } from "../dist/server/create-server.js";
import { createFolderDialog } from "../dist/server/picker/folder-dialog.js";
import { createInspectorHost } from "../dist/server/picker/inspector-host.js";
import { loadStaticAssets } from "../dist/server/static-files.js";

const homeDir = process.argv[2];
const port = Number(process.argv[3] ?? 4321);
if (homeDir === undefined || !homeDir.startsWith("/")) {
  throw new Error("Usage: code-only-preview-server.mjs <absolute home folder> [port]");
}
if (!Number.isInteger(port) || port === 4317 || port === 4318) {
  throw new Error("Pass a free port other than 4317 and 4318");
}

const never = (what) => async () => {
  throw new Error(`The code-only preview never ${what}.`);
};
const refuse = Object.assign(never("signs in to GitHub"), {
  invalidate() {},
  signOut() {},
  existing: async () => null,
});
const defaults = createDefaultServerDeps();
const assets = await loadStaticAssets(new URL("../dist/client/", import.meta.url).pathname);
const server = await startLocalWebServer({
  projectRoot: null,
  presetTargetPort: null,
  env: { HOME: homeDir },
  assets,
  port,
  ui: "simple",
  deps: {
    ...defaults,
    verifyProject: never("verifies a project with GitHub"),
    runScan: never("runs an authorized scan"),
    recheckOwnerApproval: never("asks GitHub for owner approval"),
    webScanner: never("runs local web checks"),
    createSessionProvider: () => refuse,
    credentialStore: createInMemoryCredentialStore(),
    probeLocalService: never("probes a port"),
    discoverListeningPorts: async () => ({
      ports: [],
      method: "lsof",
      isComplete: false,
      isAvailable: false,
      note: null,
    }),
    openResultStore: () => null,
    isStoreDisabled: true,
    advisoryDataDir: null,
    picker: {
      inspector: createInspectorHost(),
      storage: null,
      roots: [],
      homeDir,
      platform: process.platform,
      folderDialog: createFolderDialog(),
    },
  },
});
console.log(`code-only preview (PROTOTYPE #414, read-only, offline) on ${server.url}`);
const stop = () => void server.close().then(() => process.exit(0));
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
