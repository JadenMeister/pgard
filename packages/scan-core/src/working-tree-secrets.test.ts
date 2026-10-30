import { mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { openDirectoryNoFollow, readSmallRegularFileBytes } from "@pgard/git-history";
import { afterEach, describe, expect, it } from "vitest";
import { runCodeOnlyScan } from "./index.js";
import { scanWorkingTreeSecrets, WORKING_TREE_SECRETS_AREA } from "./working-tree-secrets.js";

// The AWS documentation key with its last letter changed (EXAMPLE itself reads as a placeholder).
const FAKE_KEY = `${"AKIA"}IOSFODNN7EXAMPLQ`;
const GITHUB_TOKEN = `ghp_${"a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"}`;

let dir: string | null = null;
afterEach(async () => {
  if (dir !== null) await rm(dir, { recursive: true, force: true });
  dir = null;
});

async function project(files: Record<string, string | Buffer>): Promise<string> {
  dir = await mkdtemp(path.join(os.tmpdir(), "pgard-codeonly-"));
  for (const [name, content] of Object.entries(files)) {
    await mkdir(path.dirname(path.join(dir, name)), { recursive: true });
    await writeFile(path.join(dir, name), content);
  }
  return dir;
}

describe("scanWorkingTreeSecrets (prototype, #414)", () => {
  it("finds a secret and a .env file on disk, never puts the value in a finding", async () => {
    const root = await project({
      "src/config.js": `export const aws = { accessKeyId: "${FAKE_KEY}" };\n`,
      ".env": "TOKEN=x\n",
      "node_modules/pkg/index.js": `const k = "${FAKE_KEY}";\n`,
    });
    const output = await scanWorkingTreeSecrets({ projectRoot: root, projectConfig: null });
    const rules = output.findings.map((finding) => `${finding.ruleId} ${finding.location.path}`);
    expect(rules).toContain("PG-SECRET-001 .env");
    expect(rules.some((entry) => entry.startsWith("PG-SECRET-002 src/config.js"))).toBe(true);
    expect(rules.some((entry) => entry.includes("node_modules"))).toBe(false);
    expect(JSON.stringify(output)).not.toContain(FAKE_KEY);
    // The file may never have been committed: no "tracked file" or "committed to Git".
    expect(output.findings.map((finding) => finding.title).sort()).toEqual([
      "Environment file in the project folder",
      "Secret in a project file",
    ]);
    expect(JSON.stringify(output)).not.toMatch(/tracked file|committed to Git|staged/i);
    expect(output.coverage[0]).toMatchObject({
      area: WORKING_TREE_SECRETS_AREA,
      scope: "code",
      status: "completed",
    });
  });

  it("never follows a symbolic link", async () => {
    const root = await project({ "real/secret.txt": `key=${FAKE_KEY}\n`, "app/a.js": "" });
    const outside = await mkdtemp(path.join(os.tmpdir(), "pgard-outside-"));
    try {
      await writeFile(path.join(outside, "s.js"), `const k = "${FAKE_KEY}";\n`);
      await symlink(outside, path.join(root, "app", "linked"));
      await symlink(path.join(outside, "s.js"), path.join(root, "app", "file-link.js"));
      const output = await scanWorkingTreeSecrets({ projectRoot: root, projectConfig: null });
      const paths = output.findings.map((finding) => finding.location.path);
      expect(paths.some((entry) => entry?.startsWith("app/"))).toBe(false);
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });
});

describe("scanWorkingTreeSecrets never reports completed for files it did not read", () => {
  const line = `const token = "${GITHUB_TOKEN}";\n`;

  it("reads UTF-16 and NUL-padded text, and names the large file (review repro)", async () => {
    const big = `${"// filler line\n".repeat(80_000)}${line}`; // over 1 MiB
    const root = await project({
      "big.js": big,
      "u16.ps1": Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(line, "utf16le")]),
      "u16-nobom.ps1": Buffer.from(line, "utf16le"),
      "nul.js": `\0${line}`,
    });
    const output = await scanWorkingTreeSecrets({ projectRoot: root, projectConfig: null });
    const paths = output.findings
      .filter((finding) => finding.ruleId === "PG-SECRET-002")
      .map((finding) => finding.location.path)
      .sort();
    expect(paths).toEqual(["nul.js", "u16-nobom.ps1", "u16.ps1"]);
    expect(output.coverage[0]?.status).toBe("partial");
    expect(output.coverage[0]?.note).toContain("big.js");
    expect(JSON.stringify(output)).not.toContain(GITHUB_TOKEN);
  });

  it("is partial for a file that only looks binary, and skips a PNG by design (review repro)", async () => {
    const log = Buffer.from(
      `${"\x1b[31mE\x1b[0m\x1b[1m\x1b[0m ok\n".repeat(600)}\0 token=${GITHUB_TOKEN}\n${"\x1b[32mI\x1b[0m\x1b[1m\x1b[0m ok\n".repeat(600)}`,
      "latin1",
    );
    const png = Buffer.concat([
      Buffer.from("\x89PNG\r\n\x1a\n\0\0\0\rIHDR", "latin1"),
      Buffer.alloc(200, 7),
    ]);
    const logged = await scanWorkingTreeSecrets({
      projectRoot: await project({ "build.log": log }),
      projectConfig: null,
    });
    expect(logged.coverage[0]?.status).toBe("partial");
    expect(logged.coverage[0]?.note).toContain("looked binary without a known file format");
    expect(logged.coverage[0]?.note).toContain("build.log");
    const image = await scanWorkingTreeSecrets({
      projectRoot: await project({ "logo.png": png }),
      projectConfig: null,
    });
    expect(image.coverage[0]?.status).toBe("completed");
    expect(image.coverage[0]?.note).toContain("binary file(s) were skipped by design: logo.png");
  });

  it("never rounds a limit down to 0 in the note", async () => {
    const root = await project({ "a.txt": "x".repeat(600), "b.txt": "y".repeat(600) });
    const output = await scanWorkingTreeSecrets(
      { projectRoot: root, projectConfig: null },
      { limits: { totalBytes: 1000, fileBytes: 700 } },
    );
    expect(output.coverage[0]?.note).toContain("<1 KiB read");
    let clock = 0;
    const timed = await scanWorkingTreeSecrets(
      { projectRoot: root, projectConfig: null },
      { limits: { timeMs: 10 }, now: () => (clock += 100) },
    );
    expect(timed.coverage[0]?.note).toContain("(<1 s)");
  });

  it("reports a .env file by its name when it is too large or binary", async () => {
    const root = await project({
      ".env": "A=1\n".repeat(400_000),
      "config/.env.local": Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0]),
    });
    const output = await scanWorkingTreeSecrets({ projectRoot: root, projectConfig: null });
    const env = output.findings
      .filter((finding) => finding.ruleId === "PG-SECRET-001")
      .map((finding) => finding.location.path)
      .sort();
    expect(env).toEqual([".env", "config/.env.local"]);
    expect(output.coverage[0]?.status).toBe("partial");
  });

  it("stops at the entry cap in a huge directory", async () => {
    const files: Record<string, string> = {};
    for (let index = 0; index < 300; index += 1) files[`f${index}.txt`] = "x\n";
    const root = await project(files);
    const output = await scanWorkingTreeSecrets(
      { projectRoot: root, projectConfig: null },
      { limits: { entries: 100 } },
    );
    expect(output.coverage[0]?.status).toBe("partial");
    expect(output.coverage[0]?.note).toContain("100 folder entries");
  });

  it("counts entries across many directories", async () => {
    const files: Record<string, string> = {};
    for (let index = 0; index < 60; index += 1) files[`d${index}/e${index}/a.txt`] = "x\n";
    const root = await project(files);
    const capped = await scanWorkingTreeSecrets(
      { projectRoot: root, projectConfig: null },
      { limits: { entries: 50 } },
    );
    expect(capped.coverage[0]?.status).toBe("partial");
    const whole = await scanWorkingTreeSecrets({ projectRoot: root, projectConfig: null });
    expect(whole.coverage[0]?.status).toBe("completed");
    expect(whole.coverage[0]?.note).toContain("60 file(s)");
  });

  it("stops at the total-bytes cap", async () => {
    const files: Record<string, string> = {};
    for (let index = 0; index < 10; index += 1) files[`f${index}.txt`] = "y".repeat(1000);
    const root = await project(files);
    const output = await scanWorkingTreeSecrets(
      { projectRoot: root, projectConfig: null },
      { limits: { totalBytes: 3500 } },
    );
    expect(output.coverage[0]?.status).toBe("partial");
    expect(output.coverage[0]?.note).toMatch(/^3 file\(s\)/);
    expect(output.coverage[0]?.note).toContain("stopped at its limit");
  });

  it("stops at the time budget and honours cancellation", async () => {
    const root = await project({ "a.txt": "x", "b.txt": "y" });
    let clock = 0;
    const timed = await scanWorkingTreeSecrets(
      { projectRoot: root, projectConfig: null },
      { limits: { timeMs: 10 }, now: () => (clock += 100) },
    );
    expect(timed.coverage[0]?.status).toBe("partial");
    const controller = new AbortController();
    controller.abort();
    await expect(
      scanWorkingTreeSecrets({ projectRoot: root, projectConfig: null, signal: controller.signal }),
    ).rejects.toThrow("aborted");
  });
});

describe("runCodeOnlyScan on a real folder without Git (prototype, #414)", () => {
  it("scans a folder that is not a Git repository and labels the result", async () => {
    const root = await project({
      "src/config.js": `export const aws = { accessKeyId: "${FAKE_KEY}" };\n`,
    });
    const result = await runCodeOnlyScan({ projectRoot: root }, { advisoryDataDir: null });
    expect(result.authorization.decision).toBe("blocked");
    expect(result.findings.some((finding) => finding.ruleId === "PG-SECRET-002")).toBe(true);
    expect(result.coverage.some((entry) => entry.area === WORKING_TREE_SECRETS_AREA)).toBe(true);
    expect(JSON.stringify(result)).not.toContain(root);
    expect(JSON.stringify(result)).not.toContain(FAKE_KEY);
  });
});

describe("scanWorkingTreeSecrets hardening (#427)", () => {
  const never = <T>(): Promise<T> => new Promise<T>(() => undefined);

  it("ignores the folder's own exclude: an excluded file is still checked, and the note says so", async () => {
    const root = await project({
      "secrets/config.js": `export const aws = "${FAKE_KEY}";\n`,
      "src/a.js": "export {};\n",
    });
    const output = await scanWorkingTreeSecrets({
      projectRoot: root,
      projectConfig: { exclude: ["secrets/**", "**/*.js"] } as never,
    });
    expect(output.findings.map((finding) => finding.location.path)).toContain("secrets/config.js");
    expect(output.coverage[0]?.note).toContain("exclude (2 patterns) is not applied");
  });

  it("is on time when a folder open never returns: partial, with the time limit named", async () => {
    const root = await project({ "a.js": "export {};\n" });
    const started = Date.now();
    const output = await scanWorkingTreeSecrets(
      { projectRoot: root, projectConfig: null },
      {
        limits: { timeMs: 100 },
        fs: { openDirectory: () => never(), readFile: readSmallRegularFileBytes },
      },
    );
    expect(Date.now() - started).toBeLessThan(3000);
    expect(output.coverage[0]).toMatchObject({ status: "partial" });
    expect(output.coverage[0]?.note).toContain("stopped at its limit");
  });

  it("is on time when reading entries or a file never returns", async () => {
    const root = await project({ "a.js": "export {};\n" });
    const hungDirectory = {
      state: "ok" as const,
      dev: 1n,
      dir: { read: () => never(), close: async () => undefined } as never,
    };
    const stuckRead = await scanWorkingTreeSecrets(
      { projectRoot: root, projectConfig: null },
      {
        limits: { timeMs: 100 },
        fs: { openDirectory: async () => hungDirectory, readFile: readSmallRegularFileBytes },
      },
    );
    expect(stuckRead.coverage[0]).toMatchObject({ status: "partial" });
    const stuckFile = await scanWorkingTreeSecrets(
      { projectRoot: root, projectConfig: null },
      {
        limits: { timeMs: 100 },
        fs: { openDirectory: openDirectoryNoFollow, readFile: () => never() },
      },
    );
    expect(stuckFile.coverage[0]).toMatchObject({ status: "partial" });
    expect(stuckFile.coverage[0]?.note).toContain("stopped at its limit");
  });

  it("returns at once on Cancel even when the file system never answers", async () => {
    const root = await project({ "a.js": "export {};\n" });
    const controller = new AbortController();
    const started = Date.now();
    const running = scanWorkingTreeSecrets(
      { projectRoot: root, projectConfig: null, signal: controller.signal },
      {
        limits: { timeMs: 60_000 },
        fs: { openDirectory: () => never(), readFile: readSmallRegularFileBytes },
      },
    );
    setTimeout(() => controller.abort(), 30);
    await expect(running).rejects.toThrow("aborted");
    expect(Date.now() - started).toBeLessThan(3000);
  });

  it("does not enter a folder on another device, and says so", async () => {
    const root = await project({ "sub/s.js": `const k = "${FAKE_KEY}";\n`, "a.js": "x\n" });
    const output = await scanWorkingTreeSecrets(
      { projectRoot: root, projectConfig: null },
      {
        fs: {
          openDirectory: async (directory, options) =>
            directory === path.join(root, "sub")
              ? { state: "unsafe", found: "mount" }
              : openDirectoryNoFollow(directory, options),
          readFile: readSmallRegularFileBytes,
        },
      },
    );
    expect(output.findings).toEqual([]);
    expect(output.coverage[0]).toMatchObject({ status: "partial" });
    expect(output.coverage[0]?.note).toContain("another device (a mount point)");
    expect(output.coverage[0]?.note).toContain("sub");
  });

  it("never follows a folder swapped for a symbolic link after the parent was listed", async () => {
    const root = await project({ "app/a.js": "x\n" });
    const outside = await mkdtemp(path.join(os.tmpdir(), "pgard-outside-"));
    try {
      await writeFile(path.join(outside, "s.js"), `const k = "${FAKE_KEY}";\n`);
      const output = await scanWorkingTreeSecrets(
        { projectRoot: root, projectConfig: null },
        {
          fs: {
            // The folder is replaced by a link just before it is opened.
            openDirectory: async (directory, options) => {
              if (directory === path.join(root, "app")) {
                await rm(directory, { recursive: true });
                await symlink(outside, directory, "junction");
              }
              return openDirectoryNoFollow(directory, options);
            },
            readFile: readSmallRegularFileBytes,
          },
        },
      );
      expect(JSON.stringify(output)).not.toContain("s.js");
      expect(output.findings).toEqual([]);
    } finally {
      await rm(outside, { recursive: true, force: true });
    }
  });
});
