import { execFileSync, spawn } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { AuthorizationOutcome } from "@pgard/policy";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createTestContext, createTestDeps, createTestIo } from "../../test-support.js";

// Each test starts several Git processes; a busy machine or a slow runner needs more than 5 s.
vi.setConfig({ testTimeout: 30_000 });

const authorizeProject =
  vi.fn<(root: string, deps: { signal?: AbortSignal }) => Promise<AuthorizationOutcome>>();

vi.mock("@pgard/policy", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@pgard/policy")>();
  return {
    ...actual,
    authorizeProject: (root: string, deps: { signal?: AbortSignal }) =>
      authorizeProject(root, deps),
  };
});

const { findGitRoot, runScan } = await import("@pgard/scan-core");
const { EXIT_CODES } = await import("../../exit-codes.js");
const { installHook } = await import("./hook.js");
const precommit = await import("./index.js");

// Assembled at run time so this file holds no literal token.
const GITHUB_TOKEN = `ghp_${"a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"}`;
const SECRET_LINE = `const token = "${GITHUB_TOKEN}";\n`;
const CHECKS = [
  "repository",
  "github_identity",
  "owner_approval",
  "current_access",
  "contribution",
] as const;
const ALLOWED: AuthorizationOutcome = {
  summary: {
    decision: "allowed",
    checks: CHECKS.map((id) => ({ id, status: "passed" as const, reason: "ok" })),
  },
  repo: "octo/app",
  repositoryId: 7,
  revision: "a".repeat(40),
};

const temps: string[] = [];
afterEach(() => {
  for (const dir of temps.splice(0)) {
    rmSync(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  }
});
beforeEach(() => {
  authorizeProject.mockReset();
  authorizeProject.mockResolvedValue(ALLOWED);
});

const GIT_ENV = (root: string) => ({
  PATH: process.env.PATH ?? "",
  HOME: root,
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_TERMINAL_PROMPT: "0",
});

function git(root: string, ...args: string[]): string {
  return execFileSync("git", args, { cwd: root, encoding: "utf8", env: GIT_ENV(root) });
}

function write(root: string, files: Record<string, string | Buffer>): void {
  for (const [name, content] of Object.entries(files)) {
    const target = path.join(root, name);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
}

function makeRepo(files: Record<string, string | Buffer> = { "README.md": "hello\n" }): string {
  const root = realpathSync.native(mkdtempSync(path.join(tmpdir(), "pgard-precommit-")));
  temps.push(root);
  git(root, "init", "-q", "-b", "main");
  git(root, "config", "commit.gpgsign", "false");
  write(root, files);
  git(root, "add", "-A");
  git(root, "-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-qm", "init");
  return root;
}

function setup(root: string, env: Record<string, string> = {}) {
  const captured = createTestIo({ cwd: root, env: { PGARD_NO_STORE: "1", ...env } });
  const deps = createTestDeps({
    findGitRoot,
    runScan,
    createSessionProvider: (() =>
      Object.assign(async () => Promise.reject(new Error("no sign-in in tests")), {
        existing: async () => null,
        invalidate: () => undefined,
        signOut: async () => undefined,
      })) as never,
  });
  return { captured, context: createTestContext(captured, deps) };
}

/** A file in a known binary format (PNG signature): skipped by design. */
const binaryBytes = (length: number) =>
  Buffer.concat([
    Buffer.from("\x89PNG\r\n\x1a\n", "latin1"),
    Buffer.from(Array.from({ length }, (_, index) => (index % 3 === 0 ? 0 : (index * 7) % 256))),
  ]);
const colouredLog = (token: string) =>
  Buffer.from(
    `${"\x1b[31mE\x1b[0m\x1b[1m\x1b[0m ok\n".repeat(600)}\0 token=${token}\n${"\x1b[32mI\x1b[0m\x1b[1m\x1b[0m ok\n".repeat(600)}`,
    "latin1",
  );

describe("a NUL byte or a size cannot hide a new secret", () => {
  it("blocks a .env file with a trailing NUL and a config.js with a token and a trailing NUL", async () => {
    const root = makeRepo();
    write(root, {
      ".env": "API_KEY=abc\n\0",
      "config.js": `${SECRET_LINE}\0`,
    });
    git(root, "add", ".env", "config.js");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.findings);
    expect(captured.stdout()).toContain("PG-SECRET-001");
    expect(captured.stdout()).toContain("PG-SECRET-002");
    expect(captured.stdout()).toContain("config.js:1");
  });

  it("flags a new .env by its name when its content is binary, and names the binary skip", async () => {
    const root = makeRepo();
    write(root, { "prod.env": binaryBytes(400), "photo.png": binaryBytes(600) });
    git(root, "add", "prod.env", "photo.png");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.findings);
    const text = captured.stdout();
    expect(text).toContain("PG-SECRET-001 prod.env");
    expect(text).toContain("Not scanned by design: 2 binary file(s)");
    expect(text).toContain("photo.png");
    expect(text).toContain("prod.env");
  });

  it("flags a new .env over the size limit by its name", async () => {
    const root = makeRepo();
    write(root, { "big.env": "A=1\n".repeat(400_000) });
    git(root, "add", "big.env");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.findings);
    expect(captured.stdout()).toContain("PG-SECRET-001 big.env");
  });

  it("lists a skipped binary on a clean run, and a large binary does not block", async () => {
    const root = makeRepo();
    write(root, { "photo.png": binaryBytes(2 * 1024 * 1024), "notes.md": "fine\n" });
    git(root, "add", "photo.png", "notes.md");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.ok);
    expect(captured.stdout()).toContain("Not scanned by design: 1 binary file(s) (photo.png)");
    expect(captured.stdout()).not.toContain("Not everything was scanned");
    expect(captured.stdout()).toContain("Commit allowed: nothing found");
  });

  it("warns about a file that only looks binary (a coloured log), and does not block the commit", async () => {
    const root = makeRepo();
    write(root, { "build.log": colouredLog(GITHUB_TOKEN) });
    git(root, "add", "build.log");
    const { captured, context } = setup(root);
    // The default policy blocks on "not scanned"; a binary-looking file is a warning only.
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.ok);
    const text = captured.stdout();
    expect(text).toContain("WARNING: 1 staged file(s) look binary but have no file format");
    expect(text).toContain("(build.log)");
    expect(text).toContain("This does not block the commit.");
    expect(text).not.toContain("Not everything was scanned");
    expect(text).not.toContain("Not scanned by design");
  });

  it("still blocks a binary-looking file's commit when something else was not scanned", async () => {
    const root = makeRepo();
    write(root, {
      "build.log": colouredLog(GITHUB_TOKEN),
      "big.txt": "x".repeat(2 * 1024 * 1024),
    });
    git(root, "add", "build.log", "big.txt");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.partial);
    expect(captured.stdout()).toContain("big.txt");
    expect(captured.stdout()).toContain("build.log");
  });

  it("says a large text file was not scanned, and how to let such commits through", async () => {
    const root = makeRepo();
    write(root, { "package-lock.json": `{"a":"${"x".repeat(2 * 1024 * 1024)}"}\n` });
    git(root, "add", "package-lock.json");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.partial);
    expect(captured.stdout()).toContain("package-lock.json");
    expect(captured.stdout()).toContain("whenNotScanned to warn");
  });
});

describe("a changed key body under an unchanged header", () => {
  const body = (seed: string) =>
    Array.from({ length: 3 }, (_, line) =>
      `${seed}${line}`.padEnd(64, "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789+/").slice(0, 64),
    ).join("\n");
  const pem = (seed: string) =>
    `-----BEGIN RSA PRIVATE KEY-----\n${body(seed)}\n-----END RSA PRIVATE KEY-----\n`;

  it("blocks, and does not print 'nothing found'", async () => {
    const root = makeRepo({ "keys/server.pem": pem("one") });
    write(root, { "keys/server.pem": pem("two") });
    git(root, "add", "keys/server.pem");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.findings);
    expect(captured.stdout()).toContain("PG-SECRET-002 keys/server.pem:1");
    expect(captured.stdout()).not.toContain("nothing found");
  });

  it("allows a commit that leaves the key alone and says it was not reported", async () => {
    const root = makeRepo({ "keys/server.pem": pem("one") });
    write(root, { "keys/server.pem": `# rotated by ops\n${pem("one")}` });
    git(root, "add", "keys/server.pem");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.ok);
    expect(captured.stdout()).toContain("were not reported");
  });
});

describe("source findings in a changed statement", () => {
  const SQL = (column: string) => `import Fastify from "fastify";
import { Pool } from "pg";
const pool = new Pool();
const app = Fastify();
app.get("/items", async (request) => {
  const { ${column} } = request.query as any;
  const { rows } = await pool.query(\`SELECT * FROM items ORDER BY \${${column}}\`);
  return rows;
});
`;

  it("reports the same rule again when its statement was edited, not when it was untouched", async () => {
    const root = makeRepo({ "src/app.ts": SQL("col") });
    write(root, { "src/app.ts": `${SQL("col")}// comment\n` });
    git(root, "add", "src/app.ts");
    const untouched = setup(root);
    expect(await precommit.runPrecommit(untouched.context)).toBe(EXIT_CODES.ok);
    expect(untouched.captured.stdout()).toContain("were not reported");
    write(root, { "src/app.ts": SQL("sortColumn") });
    git(root, "add", "src/app.ts");
    const edited = setup(root);
    expect(await precommit.runPrecommit(edited.context)).toBe(EXIT_CODES.findings);
    expect(edited.captured.stdout()).toContain("PG-SQL-001");
  });
});

describe("a big file that only starts like a binary", () => {
  it("is not scanned and blocks, like any large text file (it was never a pass)", async () => {
    const head = Buffer.alloc(8000, "abcdefghij");
    for (let index = 0; index < head.length; index += 20) head[index] = 0;
    const tail = `\nAWS_SECRET = "${"AKIA"}IOSFODNN7EXAMPLQ"\n${"ordinary text line\n".repeat(70_000)}`;
    const root = makeRepo();
    write(root, { "data.dat": Buffer.concat([head, Buffer.from(tail)]) });
    git(root, "add", "data.dat");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.partial);
    expect(captured.stdout()).toContain("Not everything was scanned");
    expect(captured.stdout()).toContain("data.dat");
    expect(captured.stdout()).not.toContain("Commit allowed: nothing found");
    expect(captured.stdout()).not.toContain("Not scanned by design: 1 binary");
  });

  it("sees a secret in a UTF-8 part after a UTF-16 part (notes.txt)", async () => {
    const root = makeRepo();
    write(root, {
      "notes.txt": Buffer.concat([
        Buffer.from("hello world\n".repeat(700), "utf16le"),
        Buffer.from(`const token = "${GITHUB_TOKEN}";\n`, "utf8"),
      ]),
    });
    git(root, "add", "notes.txt");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.findings);
    expect(captured.stdout()).toContain("PG-SECRET-002 notes.txt");
    expect(captured.stdout()).not.toContain("nothing found");
  });

  it("does not treat a text file that starts with %PDF- as binary, small or large", async () => {
    const small = makeRepo();
    write(small, { "doc.txt": `%PDF-1.4\nconst token = "${GITHUB_TOKEN}";\n` });
    git(small, "add", "doc.txt");
    const smallRun = setup(small);
    expect(await precommit.runPrecommit(smallRun.context)).toBe(EXIT_CODES.findings);
    expect(smallRun.captured.stdout()).toContain("PG-SECRET-002 doc.txt:2");

    const large = makeRepo();
    write(large, {
      "big.txt": `%PDF-1.4\n${"ordinary text line\n".repeat(70_000)}const token = "${GITHUB_TOKEN}";\n`,
    });
    git(large, "add", "big.txt");
    const largeRun = setup(large);
    expect(await precommit.runPrecommit(largeRun.context)).toBe(EXIT_CODES.partial);
    expect(largeRun.captured.stdout()).toContain("big.txt");
    expect(largeRun.captured.stdout()).not.toContain("Not scanned by design");
  });

  it("scans UTF-16 text without a byte order mark", async () => {
    const root = makeRepo();
    write(root, { "wide.txt": Buffer.from(`k = "${GITHUB_TOKEN}"\n`, "utf16le") });
    git(root, "add", "wide.txt");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.findings);
    expect(captured.stdout()).toContain("PG-SECRET-002 wide.txt:1");
  });
});

describe("suppressions come from the staged config", () => {
  const suppress = JSON.stringify({
    version: 1,
    suppressions: [{ ruleId: "PG-SECRET-002", path: "src/**", reason: "test fixture" }],
  });
  const plain = JSON.stringify({ version: 1 });

  it("applies the staged suppressions and says the working-tree file differs", async () => {
    const root = makeRepo({ "pgard.config.json": suppress });
    write(root, { "pgard.config.json": plain, "src/secret.ts": SECRET_LINE });
    git(root, "add", "src/secret.ts");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.ok);
    expect(captured.stdout()).toContain("1 suppressed");
    expect(captured.stderr()).toContain("differs from the staged copy");
  });

  it("does not apply suppressions that exist only in the working-tree file", async () => {
    const root = makeRepo({ "pgard.config.json": plain });
    write(root, { "pgard.config.json": suppress, "src/secret.ts": SECRET_LINE });
    git(root, "add", "src/secret.ts");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.findings);
    expect(captured.stderr()).toContain("differs from the staged copy");
  });

  it("an untracked config contributes nothing, and the note says so", async () => {
    const root = makeRepo();
    write(root, { "pgard.config.json": suppress, "src/secret.ts": SECRET_LINE });
    git(root, "add", "src/secret.ts");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.findings);
    expect(captured.stderr()).toContain("none of its settings are used here");
  });

  it("says nothing when the staged and working-tree files are the same", async () => {
    const root = makeRepo({ "pgard.config.json": suppress });
    write(root, { "src/secret.ts": SECRET_LINE });
    git(root, "add", "src/secret.ts");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.ok);
    expect(captured.stderr()).not.toContain("differs from the staged copy");
  });

  it("uses the staged exclude, not the working tree's", async () => {
    const sql = `import Fastify from "fastify";
import { Pool } from "pg";
const pool = new Pool();
const app = Fastify();
app.get("/items", async (request) => {
  const { col } = request.query as any;
  const { rows } = await pool.query(\`SELECT * FROM items ORDER BY \${col}\`);
  return rows;
});
`;
    const root = makeRepo({
      "pgard.config.json": JSON.stringify({ version: 1, exclude: ["legacy/**"] }),
    });
    write(root, { "pgard.config.json": plain, "legacy/app.ts": sql });
    git(root, "add", "legacy/app.ts");
    const { context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.ok);
  });
});

describe("the policy comes from the staged config", () => {
  it("ignores an untracked pgard.config.json and says so", async () => {
    const root = makeRepo();
    write(root, { "pgard.config.json": '{"version":1,"precommit":{"mode":"warn"}}' });
    write(root, { "src/secret.ts": SECRET_LINE });
    git(root, "add", "src/secret.ts");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.findings);
    expect(captured.stderr()).toContain("not tracked in Git");
  });

  it("uses the staged version when the working tree differs", async () => {
    const root = makeRepo({
      "pgard.config.json": '{"version":1,"precommit":{"mode":"warn"}}',
    });
    write(root, { "pgard.config.json": '{"version":1,"precommit":{"mode":"block"}}' });
    write(root, { "src/secret.ts": SECRET_LINE });
    git(root, "add", "src/secret.ts");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.ok);
    expect(captured.stdout()).toContain("Commit allowed (mode: warn)");
  });

  it("treats a staged config that is not valid as block", async () => {
    const root = makeRepo({ "pgard.config.json": '{"version":1,"precommit":{"mode":"off"}}' });
    write(root, { "src/secret.ts": SECRET_LINE });
    git(root, "add", "src/secret.ts");
    const { captured, context } = setup(root);
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.findings);
    expect(captured.stderr()).toContain("pgard.config.json is invalid");
  });
});

describe("timers", () => {
  it("the authorization cap does not cut the analysis", async () => {
    const root = makeRepo();
    write(root, { "src/ok.ts": "export const a = 1;\n" });
    git(root, "add", "src/ok.ts");
    const { captured, context } = setup(root);
    // The gate answers at once; reading the index afterwards takes longer than 20 ms.
    expect(await precommit.runPrecommit(context, { authTimeoutMs: 20 })).toBe(EXIT_CODES.ok);
    expect(captured.stdout()).toContain("Scanned 1 staged file(s)");
    expect(captured.stderr()).not.toContain("did not finish within");
  });

  it("warns about an unusable PGARD_PRECOMMIT_TIMEOUT_MS and uses the default", async () => {
    const root = makeRepo();
    const { captured, context } = setup(root, { PGARD_PRECOMMIT_TIMEOUT_MS: "soon" });
    expect(await precommit.runPrecommit(context)).toBe(EXIT_CODES.ok);
    expect(captured.stderr()).toContain("PGARD_PRECOMMIT_TIMEOUT_MS=soon is not a number");
  });

  it("does not warn when the variable is valid", async () => {
    const root = makeRepo();
    const { captured, context } = setup(root, { PGARD_PRECOMMIT_TIMEOUT_MS: "20000" });
    await precommit.runPrecommit(context);
    expect(captured.stderr()).not.toContain("is not a number");
  });
});

describe("merge commits", () => {
  it("says a clean merge runs pre-merge-commit, in install and in the snippet", async () => {
    const root = makeRepo();
    const installed = setup(root);
    await precommit.runPrecommitInstall(installed.context);
    expect(installed.captured.stdout()).toContain("pre-merge-commit");
    const snippet = setup(root);
    precommit.runPrecommitSnippet(snippet.context);
    expect(snippet.captured.stdout()).toContain(".git/hooks/pre-merge-commit");
    expect(snippet.captured.stdout()).toContain("500-file limit");
  });
});

describe("hook install races", () => {
  it("does not replace a hook that changed while the question was open", async () => {
    const root = makeRepo();
    const hooks = path.join(root, ".git", "hooks");
    mkdirSync(hooks, { recursive: true });
    const target = path.join(hooks, "pre-commit");
    writeFileSync(target, "#!/bin/sh\necho first\n");
    const outcome = await installHook(hooks, {
      confirmReplace: async () => {
        rmSync(target);
        writeFileSync(target, "#!/bin/sh\necho second, written meanwhile\n");
        return true;
      },
    });
    expect(outcome.kind).toBe("failed");
    expect(readFileSync(target, "utf8")).toBe("#!/bin/sh\necho second, written meanwhile\n");
    expect(existsSync(`${target}.pgard-backup`)).toBe(false);
  });

  it("picks a backup name that is free after the question", async () => {
    const root = makeRepo();
    const hooks = path.join(root, ".git", "hooks");
    mkdirSync(hooks, { recursive: true });
    const target = path.join(hooks, "pre-commit");
    writeFileSync(target, "#!/bin/sh\necho mine\n");
    const outcome = await installHook(hooks, {
      confirmReplace: async (name) => {
        expect(name).toBe("pre-commit.pgard-backup");
        writeFileSync(path.join(hooks, name), "someone else's backup\n");
        return true;
      },
    });
    expect(outcome.kind).toBe("replaced");
    expect(readFileSync(path.join(hooks, "pre-commit.pgard-backup"), "utf8")).toBe(
      "someone else's backup\n",
    );
    expect(readFileSync(path.join(hooks, "pre-commit.pgard-backup.1"), "utf8")).toBe(
      "#!/bin/sh\necho mine\n",
    );
  });
});

describe.skipIf(process.platform === "win32")("inside a real git commit", () => {
  /**
   * Runs `git commit` with a hook that stops until the test says go, so `runPrecommit` runs
   * while Git's own temporary index exists, with the `GIT_INDEX_FILE` Git really sets.
   */
  async function duringCommit<T>(
    root: string,
    commitArgs: string[],
    inside: (indexFile: string) => Promise<T>,
  ): Promise<{ result: T; exitCode: number | null }> {
    const hook = path.join(root, ".git", "hooks", "pre-commit");
    mkdirSync(path.dirname(hook), { recursive: true });
    writeFileSync(
      hook,
      `#!/bin/sh\nprintf '%s' "$GIT_INDEX_FILE" > "${root}/.git/hook-index"\nwhile [ ! -f "${root}/.git/hook-go" ]; do sleep 0.05; done\nexit 0\n`,
    );
    chmodSync(hook, 0o755);
    const child = spawn(
      "git",
      ["-c", "user.name=t", "-c", "user.email=t@example.com", "commit", "-q", ...commitArgs],
      { cwd: root, env: GIT_ENV(root), stdio: "ignore" },
    );
    const exited = new Promise<number | null>((resolve) => child.on("exit", resolve));
    const marker = path.join(root, ".git", "hook-index");
    for (let waited = 0; !existsSync(marker) && waited < 20_000; waited += 50) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    try {
      return { result: await inside(readFileSync(marker, "utf8")), exitCode: null };
    } finally {
      writeFileSync(path.join(root, ".git", "hook-go"), "go");
      // eslint-disable-next-line no-unsafe-finally
      void exited;
    }
  }

  it("git commit -a: scans the temporary index, including edits that were never staged", async () => {
    const root = makeRepo({ "a.ts": "export const a = 1;\n" });
    write(root, { "a.ts": SECRET_LINE });
    let indexFile = "";
    const { result } = await duringCommit(root, ["-a", "-m", "change"], async (index) => {
      indexFile = index;
      const { captured, context } = setup(root, { GIT_INDEX_FILE: index });
      return { code: await precommit.runPrecommit(context), text: captured.stdout() };
    });
    expect(path.basename(indexFile)).toBe("index.lock");
    expect(result.code).toBe(EXIT_CODES.findings);
    expect(result.text).toContain("PG-SECRET-002 a.ts:1");
  });

  it("git commit <path>: scans only that path, not other staged files", async () => {
    const root = makeRepo({ "a.ts": "export const a = 1;\n", "other.ts": "export const o = 1;\n" });
    write(root, { "other.ts": SECRET_LINE, "a.ts": "export const a = 2;\n" });
    git(root, "add", "other.ts");
    let indexFile = "";
    const { result } = await duringCommit(root, ["-m", "change", "a.ts"], async (index) => {
      indexFile = index;
      const { captured, context } = setup(root, { GIT_INDEX_FILE: index });
      return { code: await precommit.runPrecommit(context), text: captured.stdout() };
    });
    expect(path.basename(indexFile)).toMatch(/^next-index-\d+\.lock$/);
    expect(result.code).toBe(EXIT_CODES.ok);
    expect(result.text).toContain("Scanned 1 staged file(s)");
    expect(result.text).not.toContain("other.ts");
  });
});
