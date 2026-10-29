// Dev-only preview of the `pgard web` project picker. Not part of the package (`files` is `dist`
// only) and never started by pgard. It runs the REAL dashboard server in picker mode with a
// scripted stand-in for the inspector child process and an in-memory recent list, so the routes,
// the token/Host/Origin checks and the page are the real ones. No file system search, no GitHub,
// no scan, no keychain, no device code.
//
//   npm run build
//   node apps/local-web/dev/picker-preview-server.mjs [port]      (default 4318; never 4317)
//   open http://127.0.0.1:<port>/#token=pickerpickerpickerpickerpickerpicker
//
// Folder names to try: shop, app (two matches with the same path), locked, orphan, gitlab,
// worktree, foreign, slow (partial), evil (unsafe display), hang (a search that never ends).
import { fileURLToPath } from "node:url";
import { createInMemoryCredentialStore } from "@pgard/scan-core";
import { renderReport } from "@pgard/report";
import { loadStaticAssets } from "../dist/server/static-files.js";
import { startLocalWebServer } from "../dist/server/create-server.js";

const port = Number(process.argv[2] ?? 4318);
if (port === 4317) throw new Error("4317 is reserved for the real dashboard");
const TOKEN = "pickerpickerpickerpickerpickerpicker";
const ROOT = { path: "/home/dev/code", dev: 1, ino: 7 };
const GIT = { gitDev: 1, gitIno: 90, configDev: 1, configIno: 91 };

const segment = (name, ino) => ({ name, dev: 1, ino });
const github = (owner, name) => ({ status: "github", owner, name });
const candidate = (parents, name, ino, extra = {}) => ({
  rootIndex: 0,
  segments: [...parents.map((p, i) => segment(p, ino + i + 1)), segment(name, ino)],
  gitIdentity: { ...GIT, gitIno: ino + 50 },
  remote: github("acme", name),
  block: null,
  ...extra,
});

const WORLD = {
  shop: [candidate([], "shop", 100)],
  app: [
    candidate(["client-a"], "app", 200, { remote: github("acme", "app-a") }),
    candidate(["client-b"], "app", 300, { remote: github("acme", "app-b") }),
  ],
  locked: [
    candidate([], "locked", 400, {
      block: {
        code: "group_or_world_writable",
        paths: [
          "/home/dev/code",
          "/home/dev/code/locked/.git",
          "/home/dev/code/locked/.git/config",
        ],
      },
    }),
  ],
  orphan: [
    candidate([], "orphan", 500, {
      remote: { status: "none" },
      block: { code: "no_remote", paths: [] },
    }),
  ],
  gitlab: [
    candidate([], "gitlab", 600, {
      remote: { status: "not_github" },
      block: { code: "remote_not_github", paths: [] },
    }),
  ],
  worktree: [
    candidate([], "worktree", 700, {
      gitIdentity: null,
      remote: { status: "unreadable" },
      block: { code: "gitfile_unsupported", paths: [] },
    }),
  ],
  foreign: [
    candidate([], "foreign", 800, {
      remote: { status: "unreadable" },
      block: { code: "not_owned_by_you", paths: ["/home/dev/code"] },
    }),
  ],
  evil: [candidate([], "ev‮il\u0007", 900), candidate([], "x".repeat(450), 950)],
};

const RECENT = [
  {
    entryId: "RRRRRRRRRRRRRRRRRRRRR1",
    path: "/home/dev/code/shop",
    repo: "acme/shop",
    lastUsedAt: new Date().toISOString(),
  },
  {
    entryId: "RRRRRRRRRRRRRRRRRRRRR2",
    path: "/Users/old/projects/legacy",
    repo: "acme/legacy",
    lastUsedAt: new Date().toISOString(),
  },
];
let recentEntries = [...RECENT];
const storage = {
  dir: "/nowhere",
  readRecent: async () => ({ status: "ok", value: recentEntries }),
  writeRecent: async (entries) => {
    recentEntries = [...entries];
    return { ok: true };
  },
  readSettings: async () => ({ status: "missing" }),
  writeSettings: async () => ({ ok: true }),
  clear: async () => ({ removed: 0, warnings: [] }),
};

const done = { t: "done", stoppedBy: null, elapsedMs: 40, visited: 1234, skipped: [] };
const inspector = {
  outstandingCount: () => 0,
  stopAll: () => {},
  run(job, { onMessage }) {
    let isSettled = false;
    let settle;
    const result = new Promise((resolve) => {
      settle = resolve;
    });
    const finish = (outcome) => {
      if (isSettled) return;
      isSettled = true;
      settle(outcome);
    };
    const emit = (message) => {
      if (!isSettled) onMessage(message);
    };
    setTimeout(
      () => {
        if (job.kind === "search") {
          if (job.name === "hang") {
            emit({ t: "visited", n: 4200 });
            return; // never finishes: shows the spinner and the cancel button
          }
          if (job.name === "slow") {
            const first = candidate([], "slow-one", 1000);
            const second = candidate([], "slow-two", 1100);
            emit({ t: "found", key: 0, rootIndex: 0, segments: first.segments });
            emit({ t: "found", key: 1, rootIndex: 0, segments: second.segments });
            emit({ t: "inspected", key: 0, candidate: first });
            emit({ t: "done", stoppedBy: "time", elapsedMs: 5200, visited: 41000, skipped: [] });
            return finish({ status: "finished" });
          }
          const matches = WORLD[job.name] ?? [];
          matches.forEach((c, key) =>
            emit({ t: "found", key, rootIndex: 0, segments: c.segments }),
          );
          matches.forEach((c, key) => emit({ t: "inspected", key, candidate: c }));
          emit(done);
        } else if (job.kind === "inspect") {
          const wanted = job.segments.map((s) => s.name).join("/");
          const known = Object.values(WORLD)
            .flat()
            .find((c) => c.segments.map((s) => s.name).join("/") === wanted);
          if (known === undefined) emit({ t: "changed" });
          else {
            emit({
              t: "inspected",
              key: 0,
              candidate:
                job.mode === "recheck" ? { ...known, remote: { status: "unreadable" } } : known,
            });
          }
          emit(done);
        } else {
          for (const entry of job.entries) {
            const wanted = entry.path.split("/").slice(-1)[0];
            const known = (WORLD[wanted] ?? [])[0];
            emit({
              t: "recent",
              entryId: entry.entryId,
              outcome:
                known === undefined || !entry.path.startsWith(`${ROOT.path}/`)
                  ? { status: "outside_scope" }
                  : { status: "candidate", candidate: known },
            });
          }
          emit(done);
        }
        finish({ status: "finished" });
      },
      job.kind === "search" ? 350 : 60,
    );
    return { result, cancel: () => finish({ status: "killed", reason: "cancelled" }) };
  },
};

const OUTCOME = {
  summary: {
    decision: "allowed",
    checks: [
      "repository",
      "github_identity",
      "owner_approval",
      "current_access",
      "contribution",
    ].map((id) => ({
      id,
      status: "passed",
      reason: "Check passed (preview data).",
    })),
  },
  repo: "acme/shop",
  revision: "abc123",
};

const clientDir = fileURLToPath(new URL("../dist/client/", import.meta.url));
const assets = await loadStaticAssets(clientDir);
const server = await startLocalWebServer({
  projectRoot: null,
  presetTargetPort: null,
  env: {},
  assets,
  token: TOKEN,
  port,
  deps: {
    verifyProject: async () => OUTCOME,
    runScan: async () => {
      throw new Error("the preview never scans");
    },
    recheckOwnerApproval: async () => ({ status: "failed", reason: "preview", remedy: null }),
    createSessionProvider: () => Object.assign(async () => ({}), { invalidate() {}, signOut() {} }),
    credentialStore: createInMemoryCredentialStore(),
    webScanner: async () => ({ findings: [], coverage: [] }),
    probeLocalService: async () => {
      throw new Error("the preview never probes");
    },
    discoverListeningPorts: async () => ({
      ports: [],
      method: "lsof",
      isComplete: false,
      isAvailable: true,
      note: null,
    }),
    renderReport,
    now: Date.now,
    picker: {
      inspector,
      storage,
      roots: [ROOT, { path: "/home/dev/Developer", dev: 1, ino: 8 }],
      homeDir: "/home/dev",
      platform: "linux",
    },
  },
});
console.log(`picker preview on ${server.url}`);
process.on("SIGINT", () => void server.close().then(() => process.exit(0)));
process.on("SIGTERM", () => void server.close().then(() => process.exit(0)));
