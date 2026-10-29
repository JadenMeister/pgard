// Dev-only preview of the PROTOTYPE one-screen code-only flow (#414). Not part of the package
// (`files` is `dist` only) and never started by pgard. It runs the REAL dashboard server in picker
// mode with the simple screen, the REAL inspector child process (real search, real identity and
// ownership checks) and the REAL code-only scan of the folder you pick. It never talks to GitHub:
// the keychain is replaced by an in-memory store and the GitHub sign-in always fails, local port
// discovery and probing are disabled, and nothing is stored (no recent list, no settings).
//
//   npm run build
//   node apps/local-web/dev/code-only-preview-server.mjs <home-folder> [port]   (never 4317/4318)
//   open the printed http://127.0.0.1:<port>/#token=... URL
//
// The search folders are the default development folders under <home-folder> (`projects`,
// `code`, ...), exactly as `pgard web` derives them from $HOME. Advisory (OSV) data is read from
// <home-folder>'s PGARD data folder only if it exists there, so dependency checks report
// "not tested" unless you downloaded data into that folder.
import { loadSearchScope, resolveStoreDirectory } from "@pgard/result-store";
import { createInMemoryCredentialStore } from "@pgard/scan-core";
import { createDefaultServerDeps, startLocalWebServer } from "../dist/server/create-server.js";
import { createInspectorHost } from "../dist/server/picker/inspector-host.js";
import { loadStaticAssets } from "../dist/server/static-files.js";

const homeDir = process.argv[2];
const port = Number(process.argv[3] ?? 4321);
if (homeDir === undefined || !homeDir.startsWith("/")) {
  throw new Error("Usage: code-only-preview-server.mjs <absolute home folder> [port]");
}
if (port === 4317 || port === 4318) throw new Error("4317 and 4318 are reserved");

const scope = await loadSearchScope({ storage: null, uid: process.getuid?.(), homeDir });
for (const dropped of scope.dropped)
  console.log(`search folder skipped (${dropped.reason}): ${dropped.path}`);
if (scope.roots.length === 0) throw new Error(`No usable search folder under ${homeDir}`);
console.log(`search folders: ${scope.roots.map((root) => root.path).join(", ")}`);

const assets = await loadStaticAssets(new URL("../dist/client/", import.meta.url).pathname);
const refuse = Object.assign(
  async () => {
    throw new Error("The code-only preview never signs in to GitHub.");
  },
  { invalidate() {}, signOut() {}, existing: async () => null },
);
const defaults = createDefaultServerDeps();
const server = await startLocalWebServer({
  projectRoot: null,
  presetTargetPort: null,
  env: { HOME: homeDir },
  assets,
  port,
  ui: "simple",
  deps: {
    ...defaults,
    createSessionProvider: () => refuse,
    credentialStore: createInMemoryCredentialStore(),
    probeLocalService: async () => {
      throw new Error("the preview never probes");
    },
    discoverListeningPorts: async () => ({
      ports: [],
      method: "lsof",
      isComplete: false,
      isAvailable: false,
      note: null,
    }),
    openResultStore: () => null,
    isStoreDisabled: true,
    advisoryDataDir: resolveStoreDirectory({ env: {}, homeDir }),
    picker: {
      inspector: createInspectorHost(),
      storage: null,
      roots: scope.roots,
      homeDir,
      platform: process.platform,
    },
  },
});
console.log(`code-only preview (PROTOTYPE #414) on ${server.url}`);
const stop = () => void server.close().then(() => process.exit(0));
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
