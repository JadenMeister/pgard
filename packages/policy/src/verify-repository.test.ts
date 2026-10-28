import { execFileSync } from "node:child_process";
import path from "node:path";
import { runGit, type GitRunner } from "@pgard/git-history";
import { afterEach, describe, expect, it } from "vitest";
import {
  createGitFixture,
  type GitFixture,
} from "../../git-history/src/test-support/git-fixture.js";
import { verifyRepository } from "./checks.js";

describe("verifyRepository isolation order", () => {
  let fixture: GitFixture | null = null;
  afterEach(() => {
    fixture?.cleanup();
    fixture = null;
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
      expect(Date.now() - started).toBeLessThan(4000);
      expect(result.check.status).toBe("failed");
      expect(result.check.reason).toMatch(/alternates/);
      expect(calls.some((call) => call.includes("HEAD"))).toBe(false);
    },
  );
});
