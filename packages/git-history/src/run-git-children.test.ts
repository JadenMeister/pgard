import { execFileSync, spawn } from "node:child_process";
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { buildSync } from "esbuild";
import { afterEach, describe, expect, it } from "vitest";
import { killAllGitChildren, liveGitChildPids, runGit, type GitInvocation } from "./run-git.js";
import { createGitFixture, type GitFixture } from "./test-support/git-fixture.js";

const HEAD_LOOKUP: GitInvocation = {
  subcommand: "rev-parse",
  flags: ["--verify", "--quiet"],
  operands: ["HEAD^{commit}"],
};

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function waitFor(condition: () => boolean, ms = 5000): Promise<boolean> {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (condition()) return true;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  return condition();
}

describe.skipIf(process.platform === "win32")(
  "git child processes do not outlive their caller",
  () => {
    let fixture: GitFixture | null = null;
    afterEach(() => {
      killAllGitChildren();
      fixture?.cleanup();
      fixture = null;
    });

    /** A repository whose HEAD commit object is a FIFO: reading HEAD blocks git indefinitely. */
    function blockedRepository(): GitFixture {
      const repo = createGitFixture();
      const sha = repo.commit({});
      const objectDir = path.join(repo.root, ".git", "objects", sha.slice(0, 2));
      const objectFile = path.join(objectDir, sha.slice(2));
      chmodSync(objectDir, 0o755);
      chmodSync(objectFile, 0o644);
      rmSync(objectFile);
      execFileSync("mkfifo", [objectFile]);
      fixture = repo;
      return repo;
    }

    async function startBlocked(
      options: { signal?: AbortSignal; timeoutMs?: number } = {},
    ): Promise<{ pid: number; outcome: Promise<unknown> }> {
      const repo = blockedRepository();
      const outcome = runGit(HEAD_LOOKUP, { cwd: repo.root, ...options }).then(
        () => "resolved",
        (error: unknown) => error,
      );
      expect(await waitFor(() => liveGitChildPids().length === 1)).toBe(true);
      const pid = liveGitChildPids()[0] as number;
      await new Promise((resolve) => setTimeout(resolve, 150));
      expect(isAlive(pid)).toBe(true);
      return { pid, outcome };
    }

    it("kills the child immediately on abort", async () => {
      const controller = new AbortController();
      const { pid, outcome } = await startBlocked({ signal: controller.signal });
      controller.abort();
      expect(await outcome).toMatchObject({ kind: "cancelled" });
      expect(await waitFor(() => !isAlive(pid))).toBe(true);
    });

    it("does not start a child when the signal is already aborted", async () => {
      const repo = blockedRepository();
      const controller = new AbortController();
      controller.abort();
      await expect(
        runGit(HEAD_LOOKUP, { cwd: repo.root, signal: controller.signal }),
      ).rejects.toMatchObject({ kind: "cancelled" });
      expect(liveGitChildPids()).toEqual([]);
    });

    it("kills the child when the exit hook runs", async () => {
      expect(process.listeners("exit")).toContain(killAllGitChildren);
      const { pid, outcome } = await startBlocked();
      killAllGitChildren();
      await outcome;
      expect(await waitFor(() => !isAlive(pid))).toBe(true);
      expect(liveGitChildPids()).toEqual([]);
    });

    it("still kills the child on timeout", async () => {
      const { pid, outcome } = await startBlocked({ timeoutMs: 400 });
      expect(await outcome).toMatchObject({ kind: "timeout" });
      expect(await waitFor(() => !isAlive(pid))).toBe(true);
    });

    it.each(["SIGINT", "SIGTERM"] as const)(
      "kills the child when a process with no other %s listener is signalled",
      async (signal) => {
        const work = mkdtempSync(path.join(tmpdir(), "pgard-sole-listener-"));
        try {
          const bundle = path.join(work, "run-git.mjs");
          buildSync({
            entryPoints: [fileURLToPath(new URL("./run-git.ts", import.meta.url))],
            bundle: true,
            platform: "node",
            format: "esm",
            outfile: bundle,
            logLevel: "silent",
          });
          const script = path.join(work, "child.mjs");
          writeFileSync(
            script,
            `import { execFileSync } from "node:child_process";
import { mkdirSync, rmSync } from "node:fs";
import { runGit, liveGitChildPids } from ${JSON.stringify(pathToFileURL(bundle).href)};
const repo = ${JSON.stringify(path.join(work, "repo"))};
mkdirSync(repo);
execFileSync("git", ["init", "-q", repo]);
rmSync(repo + "/.git/HEAD");
execFileSync("mkfifo", [repo + "/.git/HEAD"]);
runGit({ subcommand: "rev-parse", flags: ["--show-toplevel"] }, { cwd: repo }).catch(() => {});
setTimeout(() => console.log("PID " + liveGitChildPids()[0]), 400);
setTimeout(() => {}, 30000);
`,
          );
          const child = spawn(process.execPath, [script], { stdio: ["ignore", "pipe", "ignore"] });
          let output = "";
          child.stdout.on("data", (chunk: Buffer) => (output += chunk.toString()));
          const exited = new Promise<string | null>((resolve) =>
            child.on("exit", (_code, killedBy) => resolve(killedBy)),
          );
          expect(await waitFor(() => /PID \d+/.test(output), 15000)).toBe(true);
          const pid = Number(/PID (\d+)/.exec(output)?.[1]);
          expect(isAlive(pid)).toBe(true);
          child.kill(signal);
          expect(await exited).toBe(signal);
          expect(await waitFor(() => !isAlive(pid))).toBe(true);
        } finally {
          rmSync(work, { recursive: true, force: true });
        }
      },
      30_000,
    );
  },
);
