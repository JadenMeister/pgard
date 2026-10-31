import { execFileSync, type ChildProcess } from "node:child_process";
import { EventEmitter } from "node:events";
import { mkdtempSync, openSync, closeSync, rmSync, writeFileSync } from "node:fs";
import { stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { Worker } from "node:worker_threads";
import { afterEach, describe, expect, it } from "vitest";
import {
  createInspectorHost,
  inspectorEnvironment,
  type SpawnInspector,
} from "./inspector-host.js";
import type { ChildMessage, InspectorJob } from "./protocol.js";
import { TIME_FACTOR, itScaled } from "../../../../../tests/support/timing.js";

const job: InspectorJob = {
  kind: "search",
  roots: [{ path: "/work/code", dev: 1, ino: 2 }],
  name: "shop",
  source: "drop",
  platform: "linux",
};

/** A stand-in for the child process: emits what a real child would and records what it receives. */
class FakeChild extends EventEmitter {
  pid: number | undefined = 4242;
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  sent: unknown[] = [];
  disconnected = false;
  unref(): void {}
  send(message: unknown, callback?: (error: Error | null) => void): boolean {
    this.sent.push(message);
    callback?.(null);
    return true;
  }
  disconnect(): void {
    this.disconnected = true;
  }
}

function fakeHost(options: { killed?: number[] } = {}) {
  const children: FakeChild[] = [];
  const spawnChild: SpawnInspector = () => {
    const child = new FakeChild();
    children.push(child);
    return child as unknown as ChildProcess;
  };
  const host = createInspectorHost({
    entry: "/not/used.js",
    spawnChild,
    killGroup: (pid) => options.killed?.push(pid),
  });
  return { host, children };
}

const done: ChildMessage = { t: "done", stoppedBy: null, elapsedMs: 5, visited: 3, skipped: [] };

describe("inspector host with a fake child", () => {
  it("sends the job over IPC and finishes on a valid done message", async () => {
    const { host, children } = fakeHost();
    const received: ChildMessage[] = [];
    const running = host.run(job, { hardMs: 5_000, onMessage: (m) => received.push(m) });
    expect(running).not.toBeNull();
    const child = children[0] as FakeChild;
    expect(child.sent).toEqual([job]);
    child.emit("message", { t: "visited", n: 7 });
    child.emit("message", done);
    expect(await running?.result).toEqual({ status: "finished" });
    expect(received.map((m) => m.t)).toEqual(["visited", "done"]);
  });

  const invalid: Array<[string, unknown]> = [
    ["an unknown message type", { t: "exec", cmd: "rm" }],
    ["an unknown key", { t: "visited", n: 1, extra: true }],
    ["a string where a number belongs", { t: "visited", n: "1" }],
    ["a negative count", { t: "visited", n: -1 }],
    [
      "a name with a slash",
      { t: "found", key: 0, rootIndex: 0, segments: [{ name: "a/b", dev: 1, ino: 1 }] },
    ],
    [
      "a dot-dot name",
      { t: "found", key: 0, rootIndex: 0, segments: [{ name: "..", dev: 1, ino: 1 }] },
    ],
    ["a root index out of range", { t: "found", key: 0, rootIndex: 5, segments: [] }],
    [
      "too many segments",
      {
        t: "found",
        key: 0,
        rootIndex: 0,
        segments: Array.from({ length: 9 }, () => ({ name: "a", dev: 1, ino: 1 })),
      },
    ],
    ["not an object", "done"],
    [
      "a selectable candidate without a github remote",
      {
        t: "inspected",
        key: 0,
        candidate: {
          rootIndex: 0,
          segments: [],
          gitIdentity: { gitDev: 1, gitIno: 1, configDev: 1, configIno: 1 },
          remote: { status: "none" },
          block: null,
        },
      },
    ],
    [
      "an unknown block code",
      {
        t: "inspected",
        key: 0,
        candidate: {
          rootIndex: 0,
          segments: [],
          gitIdentity: null,
          remote: { status: "none" },
          block: { code: "friendly", paths: [] },
        },
      },
    ],
    [
      "a github remote with a URL-like owner",
      {
        t: "inspected",
        key: 0,
        candidate: {
          rootIndex: 0,
          segments: [],
          gitIdentity: { gitDev: 1, gitIno: 1, configDev: 1, configIno: 1 },
          remote: { status: "github", owner: "evil.com/x", name: "r" },
          block: null,
        },
      },
    ],
    [
      "a remote that smuggles a URL field",
      {
        t: "inspected",
        key: 0,
        candidate: {
          rootIndex: 0,
          segments: [],
          gitIdentity: null,
          remote: { status: "not_github", url: "https://u:p@x/y" },
          block: { code: "remote_not_github", paths: [] },
        },
      },
    ],
  ];
  for (const [label, message] of invalid) {
    it(`fails the job on ${label}`, async () => {
      const { host, children } = fakeHost();
      const received: ChildMessage[] = [];
      const running = host.run(job, { hardMs: 5_000, onMessage: (m) => received.push(m) });
      (children[0] as FakeChild).emit("message", message);
      expect(await running?.result).toEqual({ status: "failed" });
      expect(received).toEqual([]);
    });
  }

  it("fails when the child exits without a done message, after a short grace period", async () => {
    const { host, children } = fakeHost();
    const running = host.run(job, { hardMs: 5_000, onMessage: () => undefined });
    (children[0] as FakeChild).emit("exit", 1, null);
    expect(await running?.result).toEqual({ status: "failed" });
  });

  it("accepts a done message that arrives right after exit (IPC order)", async () => {
    const { host, children } = fakeHost();
    const running = host.run(job, { hardMs: 5_000, onMessage: () => undefined });
    const child = children[0] as FakeChild;
    child.emit("exit", 0, null);
    child.emit("message", done);
    expect(await running?.result).toEqual({ status: "finished" });
  });

  it("kills the whole process group at the hard deadline", async () => {
    const killed: number[] = [];
    const { host } = fakeHost({ killed });
    const running = host.run(job, { hardMs: 30, onMessage: () => undefined });
    expect(await running?.result).toEqual({ status: "killed", reason: "deadline" });
    expect(killed).toEqual([4242]);
  });

  it("kills the group on cancel and on shutdown, and ignores messages after that", async () => {
    const killed: number[] = [];
    const { host, children } = fakeHost({ killed });
    const first = host.run(job, { hardMs: 5_000, onMessage: () => undefined });
    first?.cancel();
    expect(await first?.result).toEqual({ status: "killed", reason: "cancelled" });
    const received: ChildMessage[] = [];
    const second = host.run(job, { hardMs: 5_000, onMessage: (m) => received.push(m) });
    host.stopAll();
    expect(await second?.result).toEqual({ status: "killed", reason: "shutdown" });
    (children[1] as FakeChild).emit("message", done);
    expect(received).toEqual([]);
    expect(killed).toEqual([4242, 4242]);
  });

  it("refuses a third job while two killed children have not exited (503 inspector_busy)", async () => {
    const { host, children } = fakeHost({ killed: [] });
    for (let index = 0; index < 2; index += 1) {
      const running = host.run(job, { hardMs: 5_000, onMessage: () => undefined });
      running?.cancel();
      await running?.result;
    }
    expect(host.outstandingCount()).toBe(2);
    expect(host.run(job, { hardMs: 5_000, onMessage: () => undefined })).toBeNull();
    // One finally exits: a new job is accepted again.
    (children[0] as FakeChild).emit("exit", null, "SIGKILL");
    expect(host.outstandingCount()).toBe(1);
    expect(host.run(job, { hardMs: 5_000, onMessage: () => undefined })).not.toBeNull();
  });

  it("gives the child only an allowlisted environment (no token, no PGARD variable)", () => {
    const env = inspectorEnvironment({
      PATH: "/usr/bin",
      HOME: "/home/u",
      LANG: "en_US.UTF-8",
      PGARD_SESSION_TOKEN: "secret",
      GITHUB_TOKEN: "ghp_x",
      PGARD_GITHUB_APP_CLIENT_ID: "id",
      SSH_AUTH_SOCK: "/tmp/agent",
    });
    expect(Object.keys(env).sort()).toEqual([
      "HOME",
      "LANG",
      "NoDefaultCurrentDirectoryInExePath",
      "PATH",
    ]);
  });
});

describe.skipIf(process.platform === "win32")("inspector host with a real child process", () => {
  let dir: string | null = null;
  afterEach(() => {
    if (dir !== null) rmSync(dir, { recursive: true, force: true });
    dir = null;
  });

  function isAlive(pid: number): boolean {
    try {
      process.kill(pid, 0);
      return true;
    } catch {
      return false;
    }
  }

  async function waitFor(condition: () => boolean, ms = 5_000): Promise<boolean> {
    const end = Date.now() + ms;
    while (Date.now() < end) {
      if (condition()) return true;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    return condition();
  }

  /**
   * A child that blocks six libuv threadpool threads on a FIFO with no writer (the way a dead NFS
   * mount would), starts a grandchild in the same group, and reports its pid, its own pid, its
   * argument count and whether a secret from the parent's environment leaked into it.
   */
  function hangingChildScript(fifo: string): string {
    dir = mkdtempSync(path.join(tmpdir(), "pgard-host-"));
    const script = path.join(dir, "hang-child.mjs");
    writeFileSync(
      script,
      `import fs from "node:fs";
import { spawn } from "node:child_process";
process.once("message", () => {
  for (let i = 0; i < 6; i += 1) fs.open(${JSON.stringify(fifo)}, "r", () => {});
  const grandchild = spawn("sleep", ["60"], { stdio: "ignore" });
  process.send({ t: "visited", n: process.pid });
  process.send({ t: "visited", n: grandchild.pid });
  process.send({ t: "visited", n: process.argv.length });
  process.send({ t: "visited", n: process.env.PGARD_SECRET_TEST === undefined ? 0 : 1 });
  setInterval(() => {}, 1000);
});
`,
    );
    return script;
  }

  itScaled(
    "keeps the dashboard's own fs work responsive while the child's threadpool is blocked, and kills the whole group at the deadline",
    async () => {
      const fifoDir = mkdtempSync(path.join(tmpdir(), "pgard-fifo-"));
      const fifo = path.join(fifoDir, "pipe");
      execFileSync("mkfifo", [fifo]);
      process.env.PGARD_SECRET_TEST = "do-not-leak";
      try {
        const script = hangingChildScript(fifo);
        const host = createInspectorHost({ entry: script });
        const reported: number[] = [];
        const running = host.run(job, {
          hardMs: 2_000,
          onMessage: (m) => m.t === "visited" && reported.push(m.n),
        });
        expect(await waitFor(() => reported.length === 4)).toBe(true);
        const [childPid, grandchildPid, argCount, leaked] = reported as [
          number,
          number,
          number,
          number,
        ];
        // No path (or anything else) on the command line: node and the script only.
        expect(argCount).toBe(2);
        expect(leaked).toBe(0);
        // The child's threadpool is blocked; the dashboard's own fs work still answers fast.
        const started = Date.now();
        await stat(tmpdir());
        expect(Date.now() - started).toBeLessThan(1_000 * TIME_FACTOR);
        expect(isAlive(childPid)).toBe(true);
        expect(isAlive(grandchildPid)).toBe(true);
        expect(await running?.result).toEqual({ status: "killed", reason: "deadline" });
        // The whole group is gone: the child and the grandchild it started.
        expect(await waitFor(() => !isAlive(childPid) && !isAlive(grandchildPid))).toBe(true);
        // A new job works after the kill.
        const next = host.run(job, { hardMs: 500, onMessage: () => undefined });
        expect(next).not.toBeNull();
        host.stopAll();
        await next?.result;
      } finally {
        delete process.env.PGARD_SECRET_TEST;
        rmSync(fifoDir, { recursive: true, force: true });
      }
    },
    20_000,
  );

  itScaled(
    "control: the same blocking inside a worker_threads Worker freezes the dashboard's fs work",
    async () => {
      const fifoDir = mkdtempSync(path.join(tmpdir(), "pgard-fifo-"));
      const fifo = path.join(fifoDir, "pipe");
      execFileSync("mkfifo", [fifo]);
      const opened: number[] = [];
      const worker = new Worker(
        `const { workerData, parentPort } = require("node:worker_threads");
const fs = require("node:fs");
for (let i = 0; i < 6; i += 1) {
  fs.open(workerData.fifo, "r", (error, fd) => {
    parentPort.postMessage(error ? -1 : fd);
  });
}
parentPort.postMessage("started");`,
        { eval: true, workerData: { fifo } },
      );
      worker.on("message", (value) => {
        if (typeof value === "number") opened.push(value);
      });
      try {
        await new Promise((resolve) => setTimeout(resolve, 300));
        const result = await Promise.race([
          stat(tmpdir()).then(() => "stat answered"),
          new Promise<string>((resolve) => setTimeout(() => resolve("frozen"), 1_000)),
        ]);
        // This is why the inspector is a child process: four hung threads freeze every fs call here.
        expect(result).toBe("frozen");
      } finally {
        // Release the blocked threads: a writer on the FIFO lets every pending open finish.
        const writer = openSync(fifo, "r+");
        await waitFor(() => opened.length === 6, 5_000);
        closeSync(writer);
        await worker.terminate();
        rmSync(fifoDir, { recursive: true, force: true });
      }
    },
    20_000,
  );
});
