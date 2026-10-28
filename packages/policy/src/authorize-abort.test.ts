import { execFileSync } from "node:child_process";
import { chmodSync, rmSync } from "node:fs";
import path from "node:path";
import { killAllGitChildren, liveGitChildPids } from "@pgard/git-history";
import { afterEach, describe, expect, it } from "vitest";
import {
  createGitFixture,
  type GitFixture,
} from "../../git-history/src/test-support/git-fixture.js";
import { authorizeProject } from "./authorize-project.js";
import { sessionProvider } from "./test-support/mock-github.js";

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

describe.skipIf(process.platform === "win32")("abort during authorization", () => {
  let fixture: GitFixture | null = null;
  afterEach(() => {
    killAllGitChildren();
    fixture?.cleanup();
    fixture = null;
  });

  it("kills a blocked git process at once and returns quickly", async () => {
    fixture = createGitFixture({ remotes: { origin: "https://github.com/octo/app.git" } });
    const sha = fixture.commit({});
    const objectDir = path.join(fixture.root, ".git", "objects", sha.slice(0, 2));
    const objectFile = path.join(objectDir, sha.slice(2));
    chmodSync(objectDir, 0o755);
    chmodSync(objectFile, 0o644);
    rmSync(objectFile);
    execFileSync("mkfifo", [objectFile]);

    const controller = new AbortController();
    const outcome = authorizeProject(fixture.root, {
      getGitHubSession: sessionProvider(() => Promise.reject(new Error("no session"))),
      signal: controller.signal,
    }).then(
      (value) => value,
      (error: unknown) => error,
    );
    expect(await waitFor(() => liveGitChildPids().length > 0)).toBe(true);
    const pid = liveGitChildPids()[0] as number;
    const started = Date.now();
    controller.abort();
    await outcome;
    expect(Date.now() - started).toBeLessThan(3000);
    expect(await waitFor(() => !isAlive(pid))).toBe(true);
  });
});
