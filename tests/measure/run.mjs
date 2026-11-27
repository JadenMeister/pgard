// Real-repository recall measurement: `npm run measure` (see README.md; needs network, slow).
// For each case the vulnerable commit of a PUBLIC GitHub repository is fetched (shallow, only that
// commit, no authentication), checked out as plain files and scanned code-only with the built
// scan-core API (the same `runCodeOnlyScan` as `pgard scan --code-only`; no gate, no GitHub
// sign-in, nothing stored). Repository code is never executed: git only reads objects, hooks and
// filters are off (empty HOME, no system config). Run `npm run build` first.
import { execFile } from "node:child_process";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { homedir, tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs, promisify } from "node:util";
import { PGARD_VERSION, runCodeOnlyScan } from "@pgard/scan-core";
import { hasSupportedLanguage, matchCase, renderMarkdown } from "./lib.mjs";

const run = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));
const SCAN_TIMEOUT_MS = 10 * 60_000;
const GIT_TIMEOUT_MS = 10 * 60_000;

const { values: args } = parseArgs({
  options: {
    lang: { type: "string" },
    id: { type: "string", multiple: true },
    limit: { type: "string" },
    jobs: { type: "string", default: "2" },
    "fix-check": { type: "boolean", default: false },
    out: { type: "string" },
    cache: { type: "string" },
    "write-results": { type: "boolean", default: false },
  },
});

const cache = path.resolve(args.cache ?? path.join(homedir(), ".cache", "pgard-measure"));
const outDir = path.resolve(args.out ?? path.join(here, "out"));
const jobs = Math.max(1, Number(args.jobs) || 1);
const cases = JSON.parse(readFileSync(path.join(here, "cases.json"), "utf8"))
  .filter((c) => (args.lang ? c.language === args.lang : true))
  .filter((c) => (args.id?.length ? args.id.includes(c.id) : true))
  .slice(0, args.limit ? Number(args.limit) : undefined);

// No auth, no prompts, no user config: git only reads public objects over https.
const gitEnv = (home) => ({
  PATH: process.env.PATH ?? "",
  HOME: home,
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_TERMINAL_PROMPT: "0",
  GIT_LFS_SKIP_SMUDGE: "1",
});
const git = (cwd, gitArgs, extraEnv = {}) =>
  run(
    "git",
    [
      "-c",
      "core.hooksPath=/dev/null",
      "-c",
      "protocol.allow=never",
      "-c",
      "protocol.https.allow=always",
      ...gitArgs,
    ],
    {
      cwd,
      env: { ...gitEnv(cache), ...extraEnv },
      timeout: GIT_TIMEOUT_MS,
      maxBuffer: 64 * 1024 * 1024,
    },
  );

// One fetch at a time per repository (two cases of one repo share its object store).
const repoLocks = new Map();
function withRepoLock(repo, task) {
  const next = (repoLocks.get(repo) ?? Promise.resolve()).then(task, task);
  repoLocks.set(
    repo,
    next.catch(() => undefined),
  );
  return next;
}

/** Fetches one commit (depth 1) into the cache, then writes its files into a new temp folder. */
async function checkout(repo, sha) {
  const gitDir = path.join(cache, `${repo.replace("/", "__")}.git`);
  await withRepoLock(repo, async () => {
    mkdirSync(gitDir, { recursive: true });
    await git(gitDir, ["init", "-q", "--bare"]);
    try {
      await git(gitDir, ["cat-file", "-e", `${sha}^{tree}`]);
    } catch {
      await git(gitDir, [
        "fetch",
        "-q",
        "--depth",
        "1",
        "--no-tags",
        "--no-recurse-submodules",
        `https://github.com/${repo}`,
        sha,
      ]);
    }
  });
  const root = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-measure-")));
  const index = path.join(root, ".pgard-index");
  const tree = path.join(root, "tree");
  mkdirSync(tree);
  const env = { GIT_DIR: gitDir, GIT_INDEX_FILE: index, GIT_WORK_TREE: tree };
  await git(tree, ["read-tree", sha], env);
  await git(tree, ["checkout-index", "-a", "-f"], env);
  return { root, tree };
}

async function scanTree(tree) {
  const result = await runCodeOnlyScan(
    { projectRoot: tree },
    { signal: AbortSignal.timeout(SCAN_TIMEOUT_MS), advisoryDataDir: null },
  );
  return {
    // Only rule id and location are kept: no evidence text, so no secret value can leak into results.
    findings: result.findings.map((f) => ({
      ruleId: f.ruleId,
      path: f.location.path,
      line: f.location.line,
    })),
    // Area ids only (never notes). `partial` = some code area did not finish; the list says which.
    partialAreas: result.coverage.filter((c) => c.status === "partial").map((c) => c.area),
  };
}

async function measure(testCase) {
  const started = Date.now();
  const record = {
    id: testCase.id,
    language: testCase.language,
    repo: testCase.repo,
    cwe: testCase.cwe,
    doubtful: testCase.doubtful,
    inScope: testCase.inScope,
    status: "fetch-error",
    matchedRules: [],
    partial: false,
    findings: 0,
    sameFamilyInFile: 0,
    anyFindingsInFile: 0,
  };
  const finish = () => ({ ...record, wallMs: Date.now() - started });
  let work = null;
  try {
    try {
      work = await checkout(testCase.repo, testCase.vulnCommit);
    } catch (error) {
      record.error = `fetch: ${String(error.stderr ?? error.message)
        .split("\n")[0]
        .slice(0, 200)}`;
      return finish();
    }
    if (!hasSupportedLanguage(testCase)) {
      record.status = "unsupported-language";
      return finish();
    }
    // A checkout without any expected file would turn into a silent "miss": report it instead.
    if (!testCase.expect.some((r) => existsSync(path.join(work.tree, r.file)))) {
      record.error = "checkout: no expected file in the fetched tree";
      return finish();
    }
    let scan;
    try {
      scan = await scanTree(work.tree);
    } catch (error) {
      record.status = "scan-error";
      record.error = `scan: ${String(error.stderr ?? error.message)
        .split("\n")[0]
        .slice(0, 200)}`;
      return finish();
    }
    Object.assign(record, matchCase(testCase, scan.findings), {
      partial: scan.partialAreas.length > 0,
      partialAreas: scan.partialAreas,
      findings: scan.findings.length,
    });
    // Process-wide RSS after the scan (with --jobs > 1 it covers all running cases).
    record.rssMb = Math.round(process.memoryUsage().rss / 1048576);
    if (args["fix-check"] && record.status !== "miss") {
      let fixWork = null;
      try {
        fixWork = await checkout(testCase.repo, testCase.fixCommit);
        const fixed = matchCase(testCase, (await scanTree(fixWork.tree)).findings);
        record.fixSameFamilyInFile = fixed.sameFamilyInFile;
        record.fixGone = fixed.sameFamilyInFile < record.sameFamilyInFile;
      } catch (error) {
        record.fixError = String(error.stderr ?? error.message)
          .split("\n")[0]
          .slice(0, 200);
      } finally {
        if (fixWork) rmSync(fixWork.root, { recursive: true, force: true });
      }
    }
    return finish();
  } finally {
    if (work) rmSync(work.root, { recursive: true, force: true });
  }
}

mkdirSync(cache, { recursive: true });
mkdirSync(outDir, { recursive: true });
const results = new Array(cases.length);
let next = 0;
async function worker() {
  while (next < cases.length) {
    const index = next++;
    results[index] = await measure(cases[index]);
    const r = results[index];
    console.log(
      `[${index + 1}/${cases.length}] ${r.id} ${r.language} ${r.status} ${r.matchedRules.join(",")} ${r.wallMs}ms`,
    );
  }
}
await Promise.all(Array.from({ length: Math.min(jobs, cases.length) }, worker));

const meta = {
  date: new Date().toISOString().slice(0, 10),
  version: PGARD_VERSION,
  filter: [
    args.lang && `lang=${args.lang}`,
    args.id?.length && `id=${args.id.length}`,
    args.limit && `limit=${args.limit}`,
  ]
    .filter(Boolean)
    .join(", "),
};
const outFile = path.join(outDir, "results.json");
writeFileSync(outFile, `${JSON.stringify({ meta, results }, null, 2)}\n`);
const markdown = renderMarkdown(results, meta);
const mdFile = args["write-results"]
  ? path.join(here, "RESULTS-REAL.md")
  : path.join(outDir, "RESULTS-REAL.md");
writeFileSync(mdFile, markdown);
console.log(`\nWrote ${outFile}\nWrote ${mdFile}`);
