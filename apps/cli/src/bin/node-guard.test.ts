import { spawnSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import vm from "node:vm";
import { afterEach, describe, expect, it } from "vitest";
import { findOldNodeEntryProblems } from "../../../../scripts/pack-lib.mjs";
import { MIN_NODE_VERSIONS, NEWEST_NODE_LINE, isSupportedNodeVersion } from "../commands/doctor.js";

const guardPath = path.resolve(import.meta.dirname, "../../bin/pgard.js");
const guardSource = readFileSync(guardPath, "utf8");

interface GuardRun {
  stderr: string;
  exitCode: number | undefined;
  /** True when the guard went on to load the real CLI. */
  loaded: boolean;
}

/**
 * Runs the real entry file in a fresh context against a fake `process`, so an old Node.js version
 * can be simulated on any Node.js. The dynamic import is replaced by a recorder.
 */
function runGuard(
  version: string,
  options: { argv?: string[]; env?: Record<string, string>; platform?: string } = {},
): GuardRun {
  const result: GuardRun = { stderr: "", exitCode: undefined, loaded: false };
  const fakeProcess = {
    versions: { node: version },
    argv: ["node", "pgard", ...(options.argv ?? [])],
    env: options.env ?? {},
    platform: options.platform ?? "linux",
    stderr: {
      write(text: string) {
        result.stderr += text;
      },
    },
    set exitCode(code: number | undefined) {
      result.exitCode = code;
    },
    get exitCode() {
      return result.exitCode;
    },
  };
  const code = guardSource
    .replace(/^#!.*\n/, "")
    .replace('import("../dist/bin/main.js")', "__loadCli()");
  vm.runInNewContext(code, {
    process: fakeProcess,
    __loadCli: () => {
      result.loaded = true;
    },
  });
  return result;
}

const SUPPORTED = [
  "22.23.4",
  "22.23.5",
  "22.24.0",
  "22.99.0",
  "24.22.1",
  "24.22.2",
  "24.23.0",
  "26.12.1",
  "26.12.2",
  "26.13.0",
  "27.0.0",
  "30.1.2",
];
const UNSUPPORTED = [
  "14.21.3",
  "18.20.4",
  "20.19.0",
  "21.7.3",
  "22.0.0",
  "22.23.3",
  "22.22.9",
  "23.11.0",
  "24.0.0",
  "24.22.0",
  "24.21.9",
  "25.9.0",
  "26.0.0",
  "26.12.0",
  "26.11.9",
];

describe("pgard entry: Node.js version guard", () => {
  it.each(SUPPORTED)("loads the CLI on %s", (version) => {
    const run = runGuard(version);
    expect(run).toEqual({ stderr: "", exitCode: undefined, loaded: true });
  });

  it.each(UNSUPPORTED)("stops with exit code 2 and does not load the CLI on %s", (version) => {
    const run = runGuard(version);
    expect(run.loaded).toBe(false);
    expect(run.exitCode).toBe(2);
    expect(run.stderr).toContain(version);
  });

  it("agrees with doctor on every version around each boundary", () => {
    for (let major = 8; major <= 30; major += 1) {
      for (const minor of [0, 1, 11, 12, 21, 22, 23, 24, 50]) {
        for (const patch of [0, 1, 2, 3, 4, 5, 9]) {
          const version = `${major}.${minor}.${patch}`;
          expect(runGuard(version).loaded, version).toBe(isSupportedNodeVersion(version));
        }
      }
    }
  });

  it("uses the same supported range as doctor and the engines fields", () => {
    const range = `${MIN_NODE_VERSIONS.slice(0, -1)
      .map((v) => `^${v.join(".")}`)
      .join(" || ")} || >=${MIN_NODE_VERSIONS.at(-1)!.join(".")}`;
    expect(range).toBe("^22.23.4 || ^24.22.1 || >=26.12.1");
    expect(NEWEST_NODE_LINE).toBe(MIN_NODE_VERSIONS.at(-1)![0]);
    for (const file of ["package.json", "packaging/pgard/package.json"]) {
      const manifest = JSON.parse(
        readFileSync(path.resolve(import.meta.dirname, "../../../..", file), "utf8"),
      ) as { engines: { node: string } };
      expect(manifest.engines.node, file).toBe(range);
    }
    // The text shown to users names every floor of the list.
    const message = runGuard("20.0.0").stderr;
    for (const floor of MIN_NODE_VERSIONS) expect(message).toContain(floor.join("."));
  });

  it("explains the problem in English by default", () => {
    const { stderr } = runGuard("20.11.0");
    expect(stderr).toContain("pgard cannot run on this Node.js version (20.11.0).");
    expect(stderr).toContain("22.23.4");
    expect(stderr).toContain("https://nodejs.org");
    expect(stderr).toContain("winget install OpenJS.NodeJS.LTS");
    expect(stderr).toMatch(/nvm, nvm-windows or fnm/);
    expect(stderr.endsWith("\n")).toBe(true);
  });

  it("explains the problem in Korean", () => {
    const { stderr } = runGuard("20.11.0", { env: { PGARD_LANG: "ko" } });
    expect(stderr).toContain("pgard는 이 Node.js 버전(20.11.0)에서 실행할 수 없습니다.");
    expect(stderr).toContain("26.12.1");
    expect(stderr).toContain("https://nodejs.org");
    expect(stderr).toContain("winget install OpenJS.NodeJS.LTS");
    expect(stderr).toContain("nvm-windows");
  });

  describe("language rules match the CLI", () => {
    const ko = "pgard는";
    const en = "pgard cannot run";
    it.each([
      ["--lang ko", { argv: ["scan", "--lang", "ko"] }, ko],
      ["--lang=ko", { argv: ["--lang=KO"] }, ko],
      [
        "--lang en beats a Korean locale",
        { argv: ["--lang", "en"], env: { LANG: "ko_KR.UTF-8" } },
        en,
      ],
      ["--lang beats PGARD_LANG", { argv: ["--lang", "en"], env: { PGARD_LANG: "ko" } }, en],
      ["PGARD_LANG=KO", { env: { PGARD_LANG: "KO" } }, ko],
      ["PGARD_LANG=en beats a Korean locale", { env: { PGARD_LANG: "en", LANG: "ko_KR" } }, en],
      ["LANG=ko_KR.UTF-8", { env: { LANG: "ko_KR.UTF-8" } }, ko],
      ["LC_ALL=C is not overridden by a Korean LANG", { env: { LC_ALL: "C", LANG: "ko_KR" } }, en],
      ["LC_MESSAGES=ko", { env: { LC_MESSAGES: "ko" } }, ko],
      ["an empty LC_ALL is skipped", { env: { LC_ALL: "", LANG: "ko_KR" } }, ko],
      ["other locales give English", { env: { LANG: "de_DE.UTF-8" } }, en],
      [
        "an invalid PGARD_LANG falls through to the locale",
        { env: { PGARD_LANG: "fr", LANG: "ko" } },
        ko,
      ],
      ["an invalid --lang falls through", { argv: ["--lang", "xx"], env: { LANG: "ko" } }, ko],
      ["nothing set gives English", {}, en],
    ] as const)("%s", (_name, options, expected) => {
      expect(runGuard("20.0.0", options as never).stderr).toContain(expected);
    });
  });

  it("does not read Intl on non-Windows systems", () => {
    expect(runGuard("20.0.0", { platform: "darwin" }).stderr).toContain("pgard cannot run");
  });

  it("passes the real arguments and exit code through on a supported version", () => {
    // Real Node.js, real dynamic import: a copy of the entry next to a stub CLI.
    const dir = mkdtempSync(path.join(tmpdir(), "pgard guard "));
    cleanup.push(dir);
    mkdirSync(path.join(dir, "bin"));
    mkdirSync(path.join(dir, "dist/bin"), { recursive: true });
    writeFileSync(path.join(dir, "package.json"), '{"type":"module"}\n');
    copyFileSync(guardPath, path.join(dir, "bin/pgard.js"));
    writeFileSync(
      path.join(dir, "dist/bin/main.js"),
      "console.log(JSON.stringify(process.argv.slice(2)));\nprocess.exitCode = 7;\n",
    );
    const run = spawnSync(
      process.execPath,
      [path.join(dir, "bin/pgard.js"), "scan", "--x", "a b"],
      {
        encoding: "utf8",
      },
    );
    expect(run.stderr).toBe("");
    expect(JSON.parse(run.stdout)).toEqual(["scan", "--x", "a b"]);
    expect(run.status).toBe(7);
  });
});

describe("pgard entry: old-Node syntax check", () => {
  it("accepts the entry file", () => {
    expect(findOldNodeEntryProblems(guardSource)).toEqual([]);
  });

  it("has no static import, export or top-level await in its text", () => {
    expect(guardSource).not.toMatch(/^\s*(?:import|export)\b(?!\s*\()/m);
    expect(guardSource).not.toMatch(/^await\b/m);
  });

  it.each([
    ["a static import", 'import fs from "node:fs";\nfs.x();'],
    ["a side-effect import", 'import "node:fs";'],
    ["an export", "export const a = 1;"],
    ["nullish coalescing", "const a = process.env.A ?? 1;"],
    ["optional chaining", "const a = process.env?.A;"],
    ["optional catch binding", "try { a(); } catch { b(); }"],
    ["object spread", "const a = { ...process.env };"],
    ["top-level await", "await Promise.resolve();"],
  ])("rejects %s", (_name, code) => {
    expect(findOldNodeEntryProblems(code).length).toBeGreaterThan(0);
  });

  it("allows a dynamic import", () => {
    expect(findOldNodeEntryProblems('import("./main.js");')).toEqual([]);
  });
});

const cleanup: string[] = [];
afterEach(() => {
  for (const dir of cleanup.splice(0)) rmSync(dir, { recursive: true, force: true });
});
