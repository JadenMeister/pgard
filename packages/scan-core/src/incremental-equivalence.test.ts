import { execFileSync } from "node:child_process";
import { mkdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  readIncrementalState,
  readScanResult,
  type IncrementalState,
  type ScanResult,
} from "@pgard/findings";
import type { AuthorizationOutcome } from "@pgard/policy";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  createGitFixture,
  type GitFixture,
} from "../../git-history/src/test-support/git-fixture.js";
import { sessionProvider } from "../../policy/src/test-support/mock-github.js";

const authorizeProject = vi.fn<(root: string) => Promise<AuthorizationOutcome>>();
vi.mock("@pgard/policy", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@pgard/policy")>();
  return { ...actual, authorizeProject: (root: string) => authorizeProject(root) };
});
const { runScan } = await import("./index.js");

/**
 * Property test for incremental scans: whatever happens to the repository between two scans, the
 * incremental result must carry exactly the findings (and the same coverage statuses and rule
 * statistics) that a full scan of the same state reports. Scripted edit sequences cover the cases
 * the design depends on; seeded random sequences hunt for the ones nobody thought of.
 */

const TOKEN = ["ghp", "_", "WiRiNgTeStVaLuE0123", "456789AbCdEfGhIjK"].join("");
const OTHER_TOKEN = ["ghp", "_", "ZzYyXxWwVvUuTt9876", "543210QqRrSsPpOoN"].join("");

const SQL_JS = (name: string) =>
  `import { Pool } from "pg";\nconst pool = new Pool();\nexport const ${name} = (req) => pool.query(\`SELECT * FROM t WHERE id = \${req.query.id}\`);\n`;
const SERVER_JS =
  "import express from 'express';\nimport session from 'express-session';\nconst app = express();\napp.use(session({ secret: process.env.S, cookie: { secure: true, sameSite: 'lax' } }));\napp.post('/login', login);\napp.post('/items', create);\n";
const GO_SQL =
  'package main\nimport (\n\t"database/sql"\n\t"fmt"\n\t"net/http"\n)\nfunc h(db *sql.DB, w http.ResponseWriter, r *http.Request) {\n\tid := r.URL.Query().Get("id")\n\trows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %s", id))\n\t_ = rows\n}\n';
const JSX_XSS =
  "export const C = ({ html }) => <div dangerouslySetInnerHTML={{ __html: html }} />;\n";
const PACKAGE_JSON = (dependencies: Record<string, string>) =>
  `${JSON.stringify({ name: "app", version: "1.0.0", dependencies })}\n`;

const INITIAL_FILES: Record<string, string> = {
  "package.json": PACKAGE_JSON({ express: "^4.0.0", pg: "^8.0.0" }),
  ".gitignore": "ignored/\n",
  "src/a.js": SQL_JS("qa"),
  "src/b.ts": "export const b = (n: number): number => n + 1;\n",
  "src/server.js": SERVER_JS,
  "src/ui.jsx": JSX_XSS,
  "go/main.go": GO_SQL,
  "docs/readme.md": "# app\n",
};

let fixture: GitFixture | null = null;
afterEach(() => {
  fixture?.cleanup();
  fixture = null;
});

const allowed = (revision: string | null): AuthorizationOutcome => ({
  summary: {
    decision: "allowed",
    checks: (
      ["repository", "github_identity", "owner_approval", "current_access", "contribution"] as const
    ).map((id) => ({ id, status: "passed" as const, reason: "ok" })),
  },
  repo: "me/app",
  revision,
});

interface Stored {
  result: ScanResult;
  state: IncrementalState | null;
}

/** One scan of the fixture, as the CLI would run it: a base to build on, or none for a full scan. */
async function scan(
  repo: GitFixture,
  base: Stored | null,
  options: { forceFull?: boolean } = {},
): Promise<Stored> {
  const head = repo.git("rev-parse", "HEAD").trim();
  authorizeProject.mockResolvedValue(allowed(head));
  let produced: IncrementalState | null = null;
  const result = await runScan(
    { projectRoot: repo.root, scopes: ["code", "history"], webTarget: null },
    {
      authorization: {
        getGitHubSession: sessionProvider(async () => Promise.reject(new Error("unused"))),
      },
      env: {},
      incremental: {
        ...(options.forceFull ? { forceFull: true } : {}),
        loadBase: async () =>
          base === null ? { kind: "none", reason: "no_previous_scan" } : { kind: "found", base },
        onState: (state) => {
          produced = state;
        },
      },
    },
  );
  // Stored and read back, exactly like the result store does (JSON text, validated reader).
  const readResult = readScanResult(JSON.parse(JSON.stringify(result)));
  if (!readResult.ok) throw new Error("the scan produced an unreadable result");
  return {
    result: readResult.result,
    state: produced === null ? null : readIncrementalState(JSON.parse(JSON.stringify(produced))),
  };
}

/** What must be the same between an incremental and a full scan of one state. */
function comparable(result: ScanResult): unknown {
  return {
    overallStatus: result.overallStatus,
    findings: result.findings,
    // Notes carry run-specific wording (what was reused); statuses and rules must not differ.
    coverage: result.coverage.map((entry) => ({
      area: entry.area,
      status: entry.status,
      ruleIds: entry.ruleIds,
    })),
    // An incremental scan does not recount the blobs of earlier commits (it reports why).
    ruleStats: result.ruleStats?.map((stat) => ({
      ...stat,
      targets: stat.targets.filter((target) => target.unit !== "blobs"),
    })),
    standardsCoverage: result.standardsCoverage,
    target: result.target,
  };
}

/** Runs the incremental scan and a full scan of the same state and compares them. */
async function expectSameAsFull(
  repo: GitFixture,
  base: Stored,
  label: string,
): Promise<{ incremental: Stored; full: Stored }> {
  const incremental = await scan(repo, base);
  const full = await scan(repo, null);
  expect(comparable(incremental.result), label).toEqual(comparable(full.result));
  return { incremental, full };
}

function write(repo: GitFixture, file: string, content: string): void {
  repo.writeFile(file, content);
}

function commitAll(repo: GitFixture, message: string): void {
  repo.git("add", "-A");
  repo.git(
    "-c",
    "user.name=Fixture",
    "-c",
    "user.email=fixture@example.com",
    "commit",
    "-q",
    "--allow-empty",
    "-m",
    message,
  );
}

function setup(): GitFixture {
  fixture = createGitFixture();
  fixture.commit({ files: INITIAL_FILES, message: "initial" });
  write(fixture, "ignored/skipped.js", SQL_JS("ignored"));
  return fixture;
}

describe("incremental scan equals a full scan", () => {
  it("is used on a second scan and reuses unchanged files", async () => {
    const repo = setup();
    const first = await scan(repo, null);
    expect(first.result.incremental).toMatchObject({
      used: false,
      reason: "no_previous_scan",
      filesReused: 0,
    });
    expect(first.result.findings.map((f) => f.ruleId)).toEqual(
      expect.arrayContaining(["PG-SQL-001", "PG-SQL-003", "PG-CSRF-001", "PG-BRUTE-001"]),
    );
    const { incremental } = await expectSameAsFull(repo, first, "no change");
    const info = incremental.result.incremental;
    expect(info).toMatchObject({
      used: true,
      reason: null,
      basedOn: { scanId: first.result.scanId },
      filesRescanned: 0,
      commitsScanned: 0,
      code: { mode: "incremental" },
      history: { mode: "incremental" },
    });
    expect(info?.filesReused).toBe(first.result.incremental?.filesRescanned);
    expect(
      incremental.result.coverage.find((entry) => entry.area === "source:javascript")?.note,
    ).toContain(`reused from scan ${first.result.scanId.slice(0, 8)}`);
  });

  it("follows a scripted sequence of edits, one scan after each", async () => {
    const repo = setup();
    let base = await scan(repo, null);
    const step = async (label: string, edit: () => void): Promise<Stored> => {
      edit();
      const { incremental } = await expectSameAsFull(repo, base, label);
      base = incremental;
      return incremental;
    };

    // Uncommitted edit of one file: only that file is analyzed again.
    const edited = await step("edit a file", () => write(repo, "src/a.js", SQL_JS("renamed")));
    expect(edited.result.incremental).toMatchObject({ used: true, filesRescanned: 1 });

    // Untracked new file with a finding.
    await step("add an untracked file", () => write(repo, "src/c.js", SQL_JS("qc")));
    // The same state committed (the content hashes are unchanged, the commit range is not).
    await step("commit it", () => commitAll(repo, "add c"));
    // A file changed only in a gitignored directory is still scanned (the walk does not use .gitignore).
    await step("edit an ignored file", () =>
      write(repo, "ignored/skipped.js", SQL_JS("ignoredAgain")),
    );
    await step("delete a file", () => rmSync(path.join(repo.root, "src/c.js")));
    await step("rename a file (uncommitted)", () =>
      renameSync(path.join(repo.root, "src/a.js"), path.join(repo.root, "src/renamed.js")),
    );
    await step("commit the rename", () => commitAll(repo, "rename"));

    // A project-wide rule: a new file anywhere removes the CSRF finding of an unchanged file.
    const protectedStep = await step("add a CSRF library import elsewhere", () =>
      write(repo, "src/protect.js", "import csrf from 'csurf';\nexport default csrf;\n"),
    );
    expect(protectedStep.result.findings.map((f) => f.ruleId)).not.toContain("PG-CSRF-001");
    expect(protectedStep.result.incremental?.filesRescanned).toBe(1);
    await step("remove it again", () => rmSync(path.join(repo.root, "src/protect.js")));
    expect(base.result.findings.map((f) => f.ruleId)).toContain("PG-CSRF-001");

    // A manifest: declaring a rate limiter removes the brute-force finding without touching code.
    const limited = await step("declare a rate limiter in package.json", () =>
      write(
        repo,
        "package.json",
        PACKAGE_JSON({ express: "^4.0.0", pg: "^8.0.0", "express-rate-limit": "^7.0.0" }),
      ),
    );
    expect(limited.result.findings.map((f) => f.ruleId)).not.toContain("PG-BRUTE-001");
    await step("drop it again", () =>
      write(repo, "package.json", PACKAGE_JSON({ express: "^4.0.0", pg: "^8.0.0" })),
    );

    // History: a commit that adds a secret (still in the file) ...
    await step("commit a secret", () => {
      write(repo, "src/secrets.ts", `export const token = "${TOKEN}";\n`);
      commitAll(repo, "add a secret");
    });
    // ... one more commit that changes nothing about secrets ...
    await step("commit an unrelated change", () => {
      write(repo, "docs/readme.md", "# app\n\nmore\n");
      commitAll(repo, "docs");
    });
    // ... the secret removed in a later commit (now a history finding) ...
    await step("remove the secret", () => {
      write(repo, "src/secrets.ts", "export const token = process.env.TOKEN;\n");
      commitAll(repo, "remove the secret");
    });
    // ... and a second secret committed and removed in the same range.
    await step("commit and remove another secret", () => {
      write(repo, "src/other.ts", `export const t = "${OTHER_TOKEN}";\n`);
      commitAll(repo, "second secret");
      write(repo, "src/other.ts", "export const t = 1;\n");
      commitAll(repo, "remove second secret");
    });
    // A secret that is added again after it was removed becomes a current finding again.
    await step("re-add the first secret", () => {
      write(repo, "src/again.ts", `export const token = "${TOKEN}";\n`);
      commitAll(repo, "re-add");
    });
    await step("commit an environment file", () => {
      write(repo, ".env", "API_KEY=abc123\n");
      commitAll(repo, "env");
    });
    await step("remove the environment file", () => {
      repo.git("rm", "-q", ".env");
      commitAll(repo, "remove env");
    });
  }, 120_000);

  it("falls back to a full scan when the configuration changes", async () => {
    const repo = setup();
    const first = await scan(repo, null);
    write(repo, "pgard.config.json", JSON.stringify({ version: 1, exclude: ["go"] }));
    const { incremental } = await expectSameAsFull(repo, first, "config added");
    expect(incremental.result.incremental).toMatchObject({
      used: false,
      reason: "config_changed",
      basedOn: null,
      code: { mode: "full", reason: "config_changed" },
    });
    expect(incremental.result.findings.some((f) => f.location.path === "go/main.go")).toBe(false);
    // The next scan builds on the one with the configuration again.
    const again = await expectSameAsFull(repo, incremental, "config unchanged");
    expect(again.incremental.result.incremental?.used).toBe(true);
    write(repo, "pgard.config.json", JSON.stringify({ version: 1, exclude: [] }));
    const changedBack = await expectSameAsFull(repo, again.incremental, "config changed again");
    expect(changedBack.incremental.result.incremental?.reason).toBe("config_changed");
  }, 60_000);

  it("falls back to a full scan after a rebase or an amended commit", async () => {
    const repo = setup();
    write(repo, "src/x.js", SQL_JS("qx"));
    commitAll(repo, "x");
    const first = await scan(repo, null);
    // Amending replaces the commit the stored scan was made at.
    write(repo, "src/x.js", SQL_JS("qy"));
    repo.git("add", "-A");
    repo.git(
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.com",
      "commit",
      "-q",
      "--amend",
      "-m",
      "x amended",
    );
    const { incremental } = await expectSameAsFull(repo, first, "amend");
    expect(incremental.result.incremental).toMatchObject({
      used: false,
      reason: "head_not_ancestor",
    });
  }, 60_000);

  it("falls back to a full scan when the stored scan has a partial or untested rule area", async () => {
    const repo = setup();
    // Syntax errors make the TypeScript area partial.
    write(repo, "src/broken.ts", "function (");
    const first = await scan(repo, null);
    expect(first.result.coverage.find((e) => e.area === "source:typescript")?.status).toBe(
      "partial",
    );
    write(repo, "src/broken.ts", "export const ok = 1;\n");
    const { incremental } = await expectSameAsFull(repo, first, "partial base");
    expect(incremental.result.incremental).toMatchObject({
      used: false,
      reason: "previous_incomplete",
    });
  }, 60_000);

  it("falls back to a full scan when asked to, and when the saved state is missing or invalid", async () => {
    const repo = setup();
    const first = await scan(repo, null);
    const forced = await scan(repo, first, { forceFull: true });
    expect(forced.result.incremental).toMatchObject({ used: false, reason: "requested_full" });
    expect(comparable(forced.result)).toEqual(comparable(first.result));
    const noState = await scan(repo, { result: first.result, state: null });
    expect(noState.result.incremental).toMatchObject({ used: false, reason: "no_saved_state" });
    const staleKey = await scan(repo, {
      result: first.result,
      state: first.state && { ...first.state, analysisKey: "0".repeat(64) },
    });
    expect(staleKey.result.incremental).toMatchObject({ used: false, reason: "tool_changed" });
  }, 60_000);

  it("never trusts a stored file result whose hash does not match", async () => {
    const repo = setup();
    const first = await scan(repo, null);
    // A tampered state: a file's cached findings no longer match its content hash.
    const state = first.state;
    if (state === null || state.code === null) throw new Error("expected a code state");
    const tampered: IncrementalState = {
      ...state,
      code: state.code.map((file) =>
        file.path === "src/a.js" ? { ...file, hash: "f".repeat(64), findings: [] } : file,
      ),
    };
    const { incremental } = await expectSameAsFull(
      repo,
      { result: first.result, state: tampered },
      "tampered hash",
    );
    expect(incremental.result.incremental?.filesRescanned).toBe(1);
  }, 60_000);
});

// --- Seeded random edit sequences -------------------------------------------------------------

function createRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (Math.imul(state, 1664525) + 1013904223) >>> 0;
    return state / 0x100000000;
  };
}

type Operation = (repo: GitFixture, random: () => number, counter: number) => void;

const CODE_FILES = ["src/a.js", "src/b.ts", "src/ui.jsx", "src/n1.js", "src/n2.ts", "go/main.go"];

const OPERATIONS: Record<string, Operation> = {
  "edit a file": (repo, random, counter) => {
    const file = CODE_FILES[Math.floor(random() * CODE_FILES.length)] as string;
    if (file.endsWith(".go")) write(repo, file, `${GO_SQL}// edit ${counter}\n`);
    else write(repo, file, `${SQL_JS(`q${counter}`)}// edit ${counter}\n`);
  },
  "add a file": (repo, _random, counter) =>
    write(repo, `src/new${counter}.js`, SQL_JS(`n${counter}`)),
  "delete a file": (repo, random) => {
    const files = repo
      .git("ls-files", "src")
      .split("\n")
      .filter((file) => file.length > 0 && file !== "src/server.js");
    const file = files[Math.floor(random() * files.length)];
    if (file !== undefined) rmSync(path.join(repo.root, file), { force: true });
  },
  "rename a file": (repo, random, counter) => {
    const files = repo
      .git("ls-files", "src")
      .split("\n")
      .filter((file) => file.length > 0 && file !== "src/server.js");
    const file = files[Math.floor(random() * files.length)];
    if (file === undefined) return;
    const target = path.join(repo.root, `src/moved${counter}${path.extname(file)}`);
    mkdirSync(path.dirname(target), { recursive: true });
    try {
      renameSync(path.join(repo.root, file), target);
    } catch {
      // The file was already deleted in the working tree.
    }
  },
  "toggle the CSRF library": (repo) => {
    const file = path.join(repo.root, "src/protect.js");
    try {
      rmSync(file);
    } catch {
      // not there
    }
    if (!repo.git("ls-files", "src/protect.js").trim()) {
      write(repo, "src/protect.js", "import csrf from 'csurf';\nexport default csrf;\n");
    }
  },
  "change the dependencies": (repo, random) => {
    const extra: Record<string, string> = random() < 0.5 ? { "express-rate-limit": "^7.0.0" } : {};
    write(repo, "package.json", PACKAGE_JSON({ express: "^4.0.0", pg: "^8.0.0", ...extra }));
  },
  "change the configuration": (repo, random) => {
    if (random() < 0.4) rmSync(path.join(repo.root, "pgard.config.json"), { force: true });
    else {
      const patterns = random() < 0.5 ? ["go"] : ["src/n1.js"];
      write(repo, "pgard.config.json", JSON.stringify({ version: 1, exclude: patterns }));
    }
  },
  "commit a secret": (repo, _random, counter) => {
    write(repo, `src/sec${counter}.ts`, `export const t = "${TOKEN}";\n`);
    commitAll(repo, `secret ${counter}`);
  },
  "commit an environment file": (repo, _random, counter) => {
    write(repo, `.env${counter % 2 === 0 ? "" : ".local"}`, `KEY=value${counter}\n`);
    commitAll(repo, `env ${counter}`);
  },
  "remove the secrets": (repo) => {
    for (const file of repo.git("ls-files", "src").split("\n")) {
      if (/^src\/sec\d+\.ts$/.test(file)) write(repo, file, "export const t = 1;\n");
    }
    commitAll(repo, "remove the secrets");
  },
  "commit the working tree": (repo, _random, counter) => commitAll(repo, `work ${counter}`),
  "amend the last commit": (repo, _random, counter) => {
    write(repo, "docs/readme.md", `# amended ${counter}\n`);
    repo.git("add", "-A");
    repo.git(
      "-c",
      "user.name=Fixture",
      "-c",
      "user.email=fixture@example.com",
      "commit",
      "-q",
      "--amend",
      "--allow-empty",
      "-m",
      `amended ${counter}`,
    );
  },
  "reset to an earlier commit": (repo, random) => {
    const count = Number(repo.git("rev-list", "--count", "HEAD").trim());
    if (count < 3) return;
    const back = 1 + Math.floor(random() * Math.min(2, count - 1));
    execFileSync("git", ["reset", "-q", "--mixed", `HEAD~${back}`], {
      cwd: repo.root,
      env: { PATH: process.env.PATH ?? "", HOME: repo.root, GIT_CONFIG_NOSYSTEM: "1" },
    });
  },
};

describe("incremental scan equals a full scan (random sequences)", () => {
  const names = Object.keys(OPERATIONS);
  const extraSeeds = Number(process.env.PGARD_EQUIVALENCE_EXTRA_SEEDS ?? 0);
  const seeds = [
    11,
    2026,
    90210,
    ...Array.from({ length: extraSeeds }, (_, index) => 1000 + index),
  ];
  for (const seed of seeds) {
    it(`seed ${seed}`, async () => {
      const repo = setup();
      write(repo, "src/n1.js", SQL_JS("n1"));
      write(repo, "src/n2.ts", "export const n2 = (v: string) => eval(v);\n");
      commitAll(repo, "more files");
      const random = createRandom(seed);
      let base = await scan(repo, null);
      let incrementalSteps = 0;
      for (let index = 0; index < 9; index += 1) {
        const name = names[Math.floor(random() * names.length)] as string;
        (OPERATIONS[name] as Operation)(repo, random, index);
        const { incremental } = await expectSameAsFull(
          repo,
          base,
          `seed ${seed} step ${index}: ${name}`,
        );
        if (incremental.result.incremental?.used) incrementalSteps += 1;
        base = incremental;
      }
      // The sequences must not all degrade into full scans, or the test proves nothing.
      expect(incrementalSteps).toBeGreaterThan(0);
    }, 120_000);
  }
});
