import { execFileSync } from "node:child_process";
import { chmodSync, rmSync } from "node:fs";
import http from "node:http";
import path from "node:path";
import { killAllGitChildren, liveGitChildPids } from "@pgard/git-history";
import { verifyProject, type AuthorizationOutcome } from "@pgard/scan-core";
import { afterEach, describe, expect, it } from "vitest";
import {
  createGitFixture,
  type GitFixture,
} from "../../../../packages/git-history/src/test-support/git-fixture.js";
import {
  apiGet,
  apiPost,
  json,
  outcome,
  startHarness,
  SESSION,
  TOKEN,
  waitFor,
  type Harness,
} from "./test-support/web-harness.js";
import { TIME_FACTOR } from "../../../../tests/support/timing.js";

/**
 * #377: `project verify` in the dashboard can be cancelled while Git is blocked. The check gets an
 * AbortSignal that reaches every Git child process; cancel, a client that disconnects and server
 * shutdown all abort it.
 */
let harness: Harness | null = null;
let fixture: GitFixture | null = null;
afterEach(async () => {
  killAllGitChildren();
  await harness?.close();
  harness = null;
  fixture?.cleanup();
  fixture = null;
});

function isAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

/** A repository whose newest commit object is a FIFO without a writer: Git blocks reading it. */
function hostileRepository(): string {
  fixture = createGitFixture({ remotes: { origin: "https://github.com/octo/app.git" } });
  const sha = fixture.commit({});
  const objectDir = path.join(fixture.root, ".git", "objects", sha.slice(0, 2));
  const objectFile = path.join(objectDir, sha.slice(2));
  chmodSync(objectDir, 0o755);
  chmodSync(objectFile, 0o644);
  rmSync(objectFile);
  execFileSync("mkfifo", [objectFile]);
  return fixture.root;
}

describe.skipIf(process.platform === "win32")(
  "verify cancellation while Git is blocked (#377)",
  () => {
    it("POST /api/auth/cancel kills the blocked Git process at once and resets the check", async () => {
      const root = hostileRepository();
      harness = await startHarness({ fixedRoot: root, deps: { verifyProject } });
      expect((await apiPost(harness.server, "/api/auth/verify", {})).status).toBe(200);
      await waitFor(
        () => liveGitChildPids().length,
        (count) => count > 0,
        300,
      );
      const pid = liveGitChildPids()[0] as number;
      expect(json(await apiGet(harness.server, "/api/auth")).status).toBe("running");

      const started = Date.now();
      const cancelled = await apiPost(harness.server, "/api/auth/cancel", {});
      expect(cancelled.status).toBe(200);
      expect(json(cancelled).status).toBe("idle");
      expect(Date.now() - started).toBeLessThan(3_000 * TIME_FACTOR);
      await waitFor(
        () => isAlive(pid),
        (alive) => !alive,
        300,
      );
      // The late result of the aborted run never shows up, and a new check can start.
      await new Promise((resolve) => setTimeout(resolve, 100));
      expect(json(await apiGet(harness.server, "/api/auth")).status).toBe("idle");
      expect(harness.server.state.verifyController).toBeNull();
    }, 20_000);

    it("stopping the server aborts a check that waits on a blocked Git process", async () => {
      const root = hostileRepository();
      harness = await startHarness({ fixedRoot: root, deps: { verifyProject } });
      await apiPost(harness.server, "/api/auth/verify", {});
      await waitFor(
        () => liveGitChildPids().length,
        (count) => count > 0,
        300,
      );
      const pid = liveGitChildPids()[0] as number;
      const started = Date.now();
      await harness.close();
      harness = null;
      expect(Date.now() - started).toBeLessThan(3_000 * TIME_FACTOR);
      await waitFor(
        () => isAlive(pid),
        (alive) => !alive,
        300,
      );
    }, 20_000);

    it("gives the check's signal to the gate and aborts it on cancel (fake gate)", async () => {
      let signal: AbortSignal | undefined;
      harness = await startHarness({
        fixedRoot: "/work/my-project",
        deps: {
          verifyProject: (_root, deps) =>
            new Promise<AuthorizationOutcome>((resolve) => {
              signal = deps.signal;
              deps.signal?.addEventListener("abort", () => resolve(outcome()), { once: true });
            }),
        },
      });
      await apiPost(harness.server, "/api/auth/verify", {});
      expect(signal).toBeDefined();
      expect(signal?.aborted).toBe(false);
      await apiPost(harness.server, "/api/auth/cancel", {});
      expect(signal?.aborted).toBe(true);
      // The aborted run's outcome is ignored: the check stays reset.
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(json(await apiGet(harness.server, "/api/auth")).status).toBe("idle");
    });

    it("cancel is a 200 no-op when nothing runs and needs no project", async () => {
      harness = await startHarness();
      const response = await apiPost(harness.server, "/api/auth/cancel", {});
      expect(response.status).toBe(200);
      expect(json(response).status).toBe("idle");
    });

    it("aborts an owner-approval re-check when the client disconnects", async () => {
      let signal: AbortSignal | undefined;
      const install: AuthorizationOutcome = {
        ...outcome("owner_approval"),
        remedy: {
          kind: "install_app",
          missing: "installation",
          account: { login: "me", type: "User" },
          url: "https://github.com/apps/pgard/installations/new",
          canApprove: "yes",
          unavailableReason: null,
        },
      };
      harness = await startHarness({
        fixedRoot: "/work/my-project",
        deps: {
          verifyProject: async () => install,
          recheckOwnerApproval: (_root, deps) =>
            new Promise((resolve) => {
              signal = deps.signal;
              deps.signal?.addEventListener(
                "abort",
                () => resolve({ status: "unverifiable", reason: "cancelled", remedy: null }),
                { once: true },
              );
            }),
        },
      });
      await apiPost(harness.server, "/api/auth/verify", {});
      await waitFor(
        async () => json(await apiGet(harness!.server, "/api/auth")),
        (value) => value.status === "done",
      );
      const request = http.request({
        host: "127.0.0.1",
        port: harness.server.port,
        method: "POST",
        path: "/api/auth/owner-approval",
        headers: {
          host: `127.0.0.1:${harness.server.port}`,
          "x-pgard-session": SESSION,
          origin: `http://127.0.0.1:${harness.server.port}`,
          "content-type": "application/json",
        },
      });
      request.on("error", () => undefined);
      request.end("{}");
      await waitFor(
        () => signal,
        (value) => value !== undefined,
        300,
      );
      expect(signal?.aborted).toBe(false);
      request.destroy();
      await waitFor(() => signal?.aborted, Boolean, 300);
      await waitFor(
        () => harness!.server.state.ownerApprovalRecheck,
        (running) => !running,
        300,
      );
    });

    it("cancels an owner-approval re-check with the cancel route", async () => {
      let signal: AbortSignal | undefined;
      const install: AuthorizationOutcome = {
        ...outcome("owner_approval"),
        remedy: {
          kind: "install_app",
          missing: "installation",
          account: { login: "me", type: "User" },
          url: "https://github.com/apps/pgard/installations/new",
          canApprove: "yes",
          unavailableReason: null,
        },
      };
      harness = await startHarness({
        fixedRoot: "/work/my-project",
        deps: {
          verifyProject: async () => install,
          recheckOwnerApproval: (_root, deps) =>
            new Promise((resolve) => {
              signal = deps.signal;
              deps.signal?.addEventListener(
                "abort",
                () => resolve({ status: "unverifiable", reason: "cancelled", remedy: null }),
                { once: true },
              );
            }),
        },
      });
      await apiPost(harness.server, "/api/auth/verify", {});
      await waitFor(
        async () => json(await apiGet(harness!.server, "/api/auth")),
        (value) => value.status === "done",
      );
      const pending = apiPost(harness.server, "/api/auth/owner-approval", {});
      await waitFor(
        () => signal,
        (value) => value !== undefined,
        300,
      );
      await apiPost(harness.server, "/api/auth/cancel", {});
      expect(signal?.aborted).toBe(true);
      expect((await pending).status).toBe(200);
      expect(harness.server.state.ownerApprovalRecheck).toBe(false);
    });
  },
);
