import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { runGit, type GitRunner } from "@pgard/git-history";
import { afterEach, describe, expect, it } from "vitest";
import {
  createGitFixture,
  type GitFixture,
} from "../../git-history/src/test-support/git-fixture.js";
import { verifyRepository } from "./checks.js";
import { TIME_FACTOR } from "../../../tests/support/timing.js";

describe("verifyRepository isolation order", () => {
  let fixture: GitFixture | null = null;
  afterEach(() => {
    fixture?.cleanup();
    fixture = null;
  });

  it("checks isolation before reading HEAD (replace refs block, HEAD is never read)", async () => {
    fixture = createGitFixture({ remotes: { origin: "https://github.com/octo/app.git" } });
    const first = fixture.commit({});
    const second = fixture.commit({});
    fixture.git("replace", first, second);
    const calls: string[] = [];
    const runner: GitRunner = (invocation, options) => {
      calls.push(`${invocation.subcommand} ${(invocation.operands ?? []).join(" ")}`);
      return runGit(invocation, options);
    };
    const result = await verifyRepository(fixture.root, runner);
    expect(result.check.status).toBe("failed");
    expect(result.check.reason).toMatch(/replace refs/);
    expect(calls.some((call) => call.includes("HEAD"))).toBe(false);
  });

  it.skipIf(process.platform === "win32")(
    "blocks a FIFO alternates file with the alternates reason before HEAD is read",
    async () => {
      fixture = createGitFixture({ remotes: { origin: "https://github.com/octo/app.git" } });
      fixture.commit({});
      execFileSync("mkfifo", [path.join(fixture.root, ".git", "objects", "info", "alternates")]);
      const calls: string[] = [];
      const runner: GitRunner = (invocation, options) => {
        calls.push(`${invocation.subcommand} ${(invocation.operands ?? []).join(" ")}`);
        return runGit(invocation, options);
      };
      const started = Date.now();
      const result = await verifyRepository(fixture.root, runner);
      expect(Date.now() - started).toBeLessThan(4000 * TIME_FACTOR);
      expect(result.check.status).toBe("failed");
      expect(result.check.reason).toMatch(/alternates/);
      expect(calls).toEqual([]);
    },
  );

  describe.skipIf(process.platform === "win32").each(["plain", "gitfile"])(
    "%s layout: no Git process starts before the block",
    (layout) => {
      const cases: [string, (gitDir: string) => void, RegExp][] = [
        [
          "commondir symlinked to /dev/zero",
          (g) => symlinkSync("/dev/zero", path.join(g, "commondir")),
          /commondir/,
        ],
        ["commondir FIFO", (g) => execFileSync("mkfifo", [path.join(g, "commondir")]), /commondir/],
        [
          "alternates FIFO",
          (g) => execFileSync("mkfifo", [path.join(g, "objects", "info", "alternates")]),
          /alternates/,
        ],
      ];
      it.each(cases)("%s", async (_name, inject, reason) => {
        fixture = createGitFixture({ remotes: { origin: "https://github.com/octo/app.git" } });
        fixture.commit({});
        inject(path.join(fixture.root, ".git"));
        let root = fixture.root;
        let work: string | null = null;
        if (layout === "gitfile") {
          work = mkdtempSync(path.join(tmpdir(), "pgard-vr-gitfile-"));
          writeFileSync(path.join(work, ".git"), `gitdir: ${path.join(fixture.root, ".git")}\n`);
          root = work;
        }
        const calls: string[] = [];
        const runner: GitRunner = (invocation, options) => {
          calls.push(invocation.subcommand);
          return runGit(invocation, options);
        };
        try {
          const started = Date.now();
          const result = await verifyRepository(root, runner);
          expect(Date.now() - started).toBeLessThan(4000 * TIME_FACTOR);
          expect(result.check.status).toBe("failed");
          expect(result.check.reason).toMatch(reason);
          expect(calls).toEqual([]);
        } finally {
          if (work !== null) rmSync(work, { recursive: true, force: true });
        }
      });
    },
  );
});
