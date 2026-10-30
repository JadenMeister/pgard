import { execFileSync } from "node:child_process";
import {
  chmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  MAX_PROJECT_CONFIG_BYTES,
  configTestFindingCount,
  projectConfigNotices,
  readScanResult,
  type ScanRequest,
} from "@pgard/findings";
import type { AuthorizationOutcome } from "@pgard/policy";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { sessionProvider } from "../../policy/src/test-support/mock-github.js";

const authorizeProject = vi.fn<(root: string) => Promise<AuthorizationOutcome>>();

vi.mock("@pgard/policy", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@pgard/policy")>();
  return { ...actual, authorizeProject: (root: string) => authorizeProject(root) };
});

const { runScan, loadProjectConfig, describeProjectConfig } = await import("./index.js");
const { createDefaultAnalyzers } = await import("./analyzers.js");

const ALLOWED: AuthorizationOutcome = {
  summary: {
    decision: "allowed",
    checks: (
      ["repository", "github_identity", "owner_approval", "current_access", "contribution"] as const
    ).map((id) => ({ id, status: "passed" as const, reason: "ok" })),
  },
  repo: "octo/app",
  revision: "a".repeat(40),
};

const roots: string[] = [];
// The budget test leaves about 4000 files behind; deleting them synchronously on Windows has
// exceeded vitest's 10 s hook timeout (#259), so clean up asynchronously with a longer limit.
afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
}, 60_000);
beforeEach(() => {
  authorizeProject.mockReset();
  authorizeProject.mockResolvedValue(ALLOWED);
});

const SQL_VULN =
  'import { Pool } from "pg";\nconst pool = new Pool();\nexport const q = (req) => pool.query(`SELECT * FROM t WHERE id = ${req.query.id}`);\n';

function project(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-pcfg-")));
  roots.push(root);
  for (const [relative, content] of Object.entries(files)) {
    const target = path.join(root, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
  return root;
}

const SOURCES = {
  "src/db.ts": SQL_VULN,
  "legacy/old.ts": SQL_VULN,
  "e2e/flow.ts": SQL_VULN,
};

const scan = (root: string, scopes: ScanRequest["scopes"] = ["code"], analyzers = {}) =>
  runScan(
    { projectRoot: root, scopes, webTarget: null },
    {
      authorization: {
        getGitHubSession: sessionProvider(async () => Promise.reject(new Error("unused"))),
      },
      createScanId: () => "scan-1",
      now: () => new Date("2026-10-27T00:00:00Z"),
      ...(Object.keys(analyzers).length > 0 ? { analyzers } : {}),
    },
  );

const coverageOf = (result: Awaited<ReturnType<typeof scan>>, area: string) =>
  result.coverage.find((entry) => entry.area === area);

describe("loadProjectConfig", () => {
  it("is absent when there is no file", async () => {
    expect(await loadProjectConfig(project({}))).toEqual({ state: "absent" });
  });

  it("loads a valid file", async () => {
    const root = project({ "pgard.config.json": '{"version":1,"exclude":["legacy"]}' });
    expect(await loadProjectConfig(root)).toEqual({
      state: "loaded",
      config: { version: 1, exclude: ["legacy"], testDirectories: [], suppressions: [] },
    });
  });

  it("refuses a symbolic link, even to a valid file", async () => {
    const root = project({ "real.json": '{"version":1}' });
    symlinkSync(path.join(root, "real.json"), path.join(root, "pgard.config.json"));
    const result = await loadProjectConfig(root);
    expect(result).toMatchObject({ state: "invalid" });
    expect(JSON.stringify(result)).toContain("symbolic link");
  });

  it("refuses a symbolic link to a file outside the repository", async () => {
    const outside = project({ "secret.json": '{"version":1,"exclude":["**"]}' });
    const root = project({});
    symlinkSync(path.join(outside, "secret.json"), path.join(root, "pgard.config.json"));
    expect((await loadProjectConfig(root)).state).toBe("invalid");
  });

  it("refuses a directory in place of the file", async () => {
    const root = project({ "pgard.config.json/x": "" });
    expect(await loadProjectConfig(root)).toMatchObject({ state: "invalid" });
  });

  it("refuses a file over the size cap without parsing it", async () => {
    const root = project({
      "pgard.config.json": `{"version":1,"exclude":["${"a".repeat(MAX_PROJECT_CONFIG_BYTES)}"]}`,
    });
    const result = await loadProjectConfig(root);
    expect(result).toMatchObject({ state: "invalid" });
    expect(JSON.stringify(result)).toContain("larger than 65536 bytes");
  });

  it("accepts a file exactly at the cap", async () => {
    const head = '{"version":1,"exclude":[],"x":"';
    const tail = '"}';
    const pad = " ".repeat(MAX_PROJECT_CONFIG_BYTES - head.length - tail.length);
    const root = project({ "pgard.config.json": `${head}${pad}${tail}` });
    // Size is fine; the unknown key "x" is what makes it invalid.
    expect(JSON.stringify(await loadProjectConfig(root))).not.toContain("larger than");
  });

  it("refuses invalid UTF-8", async () => {
    const root = project({});
    writeFileSync(path.join(root, "pgard.config.json"), Buffer.from([0x7b, 0xff, 0xfe, 0x7d]));
    expect(JSON.stringify(await loadProjectConfig(root))).toContain("not valid UTF-8");
  });

  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "reports an unreadable file as invalid, not as absent",
    async () => {
      const root = project({ "pgard.config.json": '{"version":1}' });
      chmodSync(path.join(root, "pgard.config.json"), 0o000);
      expect((await loadProjectConfig(root)).state).toBe("invalid");
    },
  );

  it("never executes the file: a JavaScript-looking config is just invalid", async () => {
    const root = project({
      "pgard.config.json": 'require("child_process").execSync("touch pwned"); module.exports = {}',
    });
    expect((await loadProjectConfig(root)).state).toBe("invalid");
  });
});

describe("loadProjectConfig races and size checks", () => {
  const valid = '{"version":1}';

  it("the stat check and the read check each refuse an oversized file, with their own message", async () => {
    const big = project({ "pgard.config.json": " ".repeat(MAX_PROJECT_CONFIG_BYTES + 1) });
    expect(JSON.stringify(await loadProjectConfig(big))).toContain("is larger than");
    // The file passes the stat check, then grows before it is read.
    const grows = project({ "pgard.config.json": valid });
    const result = await loadProjectConfig(grows, {
      afterInspect: () =>
        writeFileSync(
          path.join(grows, "pgard.config.json"),
          " ".repeat(MAX_PROJECT_CONFIG_BYTES + 5),
        ),
    });
    expect(JSON.stringify(result)).toContain("grew larger than");
  });

  it("accepts a file of exactly the cap (the limit is inclusive)", async () => {
    const pad = " ".repeat(MAX_PROJECT_CONFIG_BYTES - valid.length);
    const root = project({ "pgard.config.json": `${valid}${pad}` });
    expect((await loadProjectConfig(root)).state).toBe("loaded");
  });

  it.skipIf(process.platform === "win32")(
    "O_NOFOLLOW refuses a file swapped for a link to the same file after the inspection",
    async () => {
      const root = project({ "pgard.config.json": valid });
      const file = path.join(root, "pgard.config.json");
      // A hard link keeps the same device and inode, so only O_NOFOLLOW can tell the link.
      linkSync(file, path.join(root, "same-inode.json"));
      const result = await loadProjectConfig(root, {
        afterInspect: () => {
          rmSync(file);
          symlinkSync(path.join(root, "same-inode.json"), file);
        },
      });
      expect(result.state).toBe("invalid");
    },
  );

  it.skipIf(process.platform === "win32")(
    "without O_NOFOLLOW the opened file must be the inspected one (device and inode)",
    async () => {
      const outside = project({ "evil.json": '{"version":1,"exclude":["**"]}' });
      const root = project({ "pgard.config.json": valid });
      const file = path.join(root, "pgard.config.json");
      const result = await loadProjectConfig(root, {
        pretendNoNoFollow: true,
        afterInspect: () => {
          rmSync(file);
          symlinkSync(path.join(outside, "evil.json"), file);
        },
      });
      expect(result).toMatchObject({ state: "invalid" });
      expect(JSON.stringify(result)).toContain("changed while it was being opened");
      // And a normal read still works in that mode.
      expect(
        (
          await loadProjectConfig(project({ "pgard.config.json": valid }), {
            pretendNoNoFollow: true,
          })
        ).state,
      ).toBe("loaded");
    },
  );
});

describe("describeProjectConfig", () => {
  it("counts the suppressions it was given", () => {
    const coverage = describeProjectConfig(
      {
        state: "loaded",
        config: {
          version: 1,
          exclude: [],
          testDirectories: ["e2e"],
          suppressions: [{ ruleId: "PG-SQL-001", path: "a", reason: "why" }],
        },
      },
      2,
    );
    expect(coverage?.status).toBe("completed");
    expect(coverage?.note).toContain("1 suppression.");
    expect(coverage?.note).toContain("2 findings classified as test code");
  });

  it("is silent without a file", () => {
    expect(describeProjectConfig({ state: "absent" }, 0)).toBeNull();
  });
});

describe("runScan with pgard.config.json", () => {
  it("does not analyze excluded files, counts them, and keeps the JSON result valid", async () => {
    const root = project({
      ...SOURCES,
      "pgard.config.json": '{"version":1,"exclude":["legacy/**"]}',
    });
    const result = await scan(root);
    expect(result.findings.map((f) => f.location.path).sort()).toEqual([
      "e2e/flow.ts",
      "src/db.ts",
    ]);
    const excluded = coverageOf(result, "source:config-excluded");
    expect(excluded?.note).toMatch(/^1 file excluded by pgard\.config\.json/);
    expect(excluded?.note).toContain('"legacy/**"');
    expect(coverageOf(result, "source:config")?.status).toBe("completed");
    // The coverage reaches the JSON result unchanged.
    const parsed = readScanResult(JSON.parse(JSON.stringify(result)));
    expect(parsed.ok).toBe(true);
    expect(parsed.ok && parsed.result.coverage.map((c) => c.area)).toContain(
      "source:config-excluded",
    );
  });

  it("testDirectories add the test context and report how many findings they moved", async () => {
    const root = project({
      ...SOURCES,
      "pgard.config.json": '{"version":1,"testDirectories":["e2e"]}',
    });
    const result = await scan(root);
    const byPath = Object.fromEntries(result.findings.map((f) => [f.location.path, f]));
    expect(byPath["e2e/flow.ts"]?.context).toBe("test");
    expect(byPath["e2e/flow.ts"]?.confidence).toBe("low");
    expect(byPath["src/db.ts"]?.context).toBeUndefined();
    expect(coverageOf(result, "source:config")?.note).toContain(
      "1 finding classified as test code by it",
    );
  });

  it("testDirectories cannot remove the test context of a built-in test path", async () => {
    const root = project({
      "tests/a.ts": SQL_VULN,
      "pgard.config.json": '{"version":1,"testDirectories":["nothing-here"]}',
    });
    const result = await scan(root);
    expect(result.findings[0]?.context).toBe("test");
    expect(coverageOf(result, "source:config")?.note).toContain("0 findings classified");
  });

  it("testDirectories do not apply to history findings", async () => {
    const root = project({
      "pgard.config.json": '{"version":1,"testDirectories":["e2e"]}',
    });
    const historyFinding = {
      id: "h1",
      ruleId: "PG-SECRET-003",
      title: "Secret in history",
      category: "secret_exposure" as const,
      severity: "high" as const,
      status: "suspected" as const,
      confidence: "medium" as const,
      location: { kind: "commit" as const, path: "e2e/.env", line: 1, url: null, commit: "abc" },
      evidence: "key added (value redacted)",
      impact: "i",
      recommendation: "r",
      references: { cwe: [], owasp: [], cve: [] },
      sources: ["history" as const],
    };
    const result = await scan(root, ["code", "history"], {
      code: async () => ({ findings: [], coverage: [] }),
      history: async () => ({
        findings: [historyFinding],
        coverage: [
          {
            area: "history:secrets",
            scope: "history",
            status: "completed",
            ruleIds: [],
            note: null,
          },
        ],
      }),
    });
    expect(result.findings[0]?.context).toBeUndefined();
    expect(result.findings[0]?.confidence).toBe("medium");
  });

  it.each(["*.*", "src"])(
    "testDirectories %j cannot quietly demote production findings",
    async (pattern) => {
      const root = project({
        "src/a.ts": SQL_VULN,
        "src/b.ts": SQL_VULN,
        "src/c.ts": SQL_VULN,
        "pgard.config.json": JSON.stringify({ version: 1, testDirectories: [pattern] }),
      });
      const result = await scan(root, ["code"]);
      const demoted = result.findings.filter((f) => f.context === "test");
      expect(demoted.length).toBeGreaterThan(0);
      // The warning area exists, is partial (exit code 4) and says why.
      const entry = coverageOf(result, "source:config-test");
      expect(entry?.status).toBe("partial");
      expect(result.overallStatus).toBe("partial");
      expect(demoted).toHaveLength(3);
      // The notices every front end shows include the reclassification count.
      const notices = projectConfigNotices(result.coverage)
        .map((n) => n.text)
        .join("\n");
      expect(notices).toContain(`${demoted.length} finding`);
      expect(notices).toContain("classified as test code by the testDirectories setting");
      expect(configTestFindingCount(result.coverage)).toBe(demoted.length);
    },
  );

  it("testDirectories that demote every production file make the scan partial", async () => {
    const root = project({
      "src/a.ts": SQL_VULN,
      "src/b.ts": SQL_VULN,
      "pgard.config.json": '{"version":1,"testDirectories":["*.*"]}',
    });
    const result = await scan(root, ["code"]);
    expect(result.overallStatus).toBe("partial");
    expect(coverageOf(result, "source:config-test")?.status).toBe("partial");
    expect(result.findings).toHaveLength(2); // still listed, never dropped
  });

  it("a legitimate testDirectories config still shows the reclassification notice", async () => {
    const root = project({
      ...SOURCES,
      "pgard.config.json": '{"version":1,"testDirectories":["e2e"]}',
    });
    const result = await scan(root, ["code"]);
    expect(result.overallStatus).toBe("completed");
    expect(
      projectConfigNotices(result.coverage)
        .map((n) => n.text)
        .join(),
    ).toContain("1 finding was classified as test code");
  });

  it("a malicious config that excludes everything is surfaced as partial with a warning", async () => {
    const root = project({
      ...SOURCES,
      "pgard.config.json": '{"version":1,"exclude":["**"]}',
    });
    const result = await scan(root);
    expect(result.findings).toEqual([]);
    expect(result.overallStatus).toBe("partial");
    const excluded = coverageOf(result, "source:config-excluded");
    expect(excluded?.status).toBe("partial");
    expect(excluded?.note).toMatch(/^3 files excluded by pgard\.config\.json/);
    expect(excluded?.note).toContain("WARNING");
  });

  it("a config that marks every path as test code is surfaced, and findings are still listed", async () => {
    const root = project({
      ...SOURCES,
      "pgard.config.json": '{"version":1,"testDirectories":["**"]}',
    });
    const result = await scan(root);
    expect(result.findings).toHaveLength(3);
    expect(result.findings.every((f) => f.context === "test")).toBe(true);
    const config = coverageOf(result, "source:config");
    expect(config?.status).toBe("partial");
    expect(config?.note).toContain("WARNING");
    expect(config?.note).toContain("3 findings classified as test code");
  });

  it("fail-safe: an invalid config is ignored as a whole and reported, nothing is hidden", async () => {
    const root = project({
      ...SOURCES,
      "pgard.config.json": '{"version":1,"exclude":["legacy"],"allowedHosts":["evil.test"]}',
    });
    const result = await scan(root);
    expect(result.findings).toHaveLength(3); // the valid `exclude` is NOT applied either
    expect(coverageOf(result, "source:config-excluded")).toBeUndefined();
    const config = coverageOf(result, "source:config");
    expect(config?.status).toBe("partial");
    expect(config?.note).toContain("invalid and was ignored");
    expect(config?.note).toContain("allowedHosts");
    expect(result.overallStatus).toBe("partial");
  });

  it("the authorization gate and web target rules are untouched by any config", async () => {
    const root = project({
      ...SOURCES,
      "pgard.config.json":
        '{"version":1,"authorization":"skip","webTarget":"http://evil.test","ports":[1]}',
    });
    const result = await scan(root, ["code", "web"]);
    expect(authorizeProject).toHaveBeenCalledTimes(1);
    expect(coverageOf(result, "source:config")?.status).toBe("partial");
    expect(result.target.webOrigin).toBeNull();
    expect(coverageOf(result, "web")?.status).toBe("not_tested");
  });

  it("does not read the config when authorization blocks the scan", async () => {
    authorizeProject.mockResolvedValue({
      ...ALLOWED,
      summary: { ...ALLOWED.summary, decision: "blocked" },
    });
    const root = project({ ...SOURCES, "pgard.config.json": "{" });
    const result = await scan(root);
    expect(result.overallStatus).toBe("blocked");
    expect(result.coverage.map((c) => c.area)).not.toContain("source:config");
  });

  it("a scan with no config file has no config coverage", async () => {
    const result = await scan(project(SOURCES));
    expect(result.coverage.map((c) => c.area)).not.toContain("source:config");
    expect(result.coverage.map((c) => c.area)).not.toContain("source:config-excluded");
  });
});

describe("history scan and excludes", () => {
  function gitProject(): string {
    const root = project({
      "src/db.ts": SQL_VULN,
      ".env": "AWS_SECRET_ACCESS_KEY=abcdEFGH1234abcdEFGH1234abcdEFGH1234abcd\n",
      "pgard.config.json": '{"version":1,"exclude":[".env","src"]}',
    });
    const git = (...args: string[]) =>
      execFileSync("git", ["-c", "user.name=t", "-c", "user.email=t@t.test", ...args], {
        cwd: root,
        stdio: "ignore",
        timeout: 60_000,
        killSignal: "SIGKILL",
      });
    git("init", "-q");
    git("add", "-A");
    git("commit", "-q", "-m", "init", "--no-gpg-sign");
    return root;
  }

  it("excludes do not apply to history: the secret in an excluded file is still reported", async () => {
    const root = gitProject();
    const revision = execFileSync("git", ["rev-parse", "HEAD"], {
      cwd: root,
      timeout: 60_000,
      killSignal: "SIGKILL",
    })
      .toString()
      .trim();
    const output = await createDefaultAnalyzers().history({
      projectRoot: root,
      revision,
      env: {},
      now: () => new Date(),
      projectConfig: {
        version: 1,
        exclude: [".env", "src"],
        testDirectories: [],
        suppressions: [],
      },
    });
    expect(output.findings.some((f) => f.location.path === ".env")).toBe(true);
    const note = output.coverage.find((c) => c.area === "history:config-excluded");
    expect(note?.scope).toBe("history");
    expect(note?.ruleIds).toEqual([]);
    expect(note?.note).toContain("do not apply to Git history");
    expect(note?.note).toMatch(/set [0-9a-f]{16}/);
  });

  it("adds no history note when there are no excludes", async () => {
    const root = gitProject();
    const output = await createDefaultAnalyzers().history({
      projectRoot: root,
      revision: null,
      env: {},
      now: () => new Date(),
      projectConfig: null,
    });
    expect(output.coverage.map((c) => c.area)).not.toContain("history:config-excluded");
  });
});

describe("pattern work budget", () => {
  const hostile = (kind: "exclude" | "testDirectories") =>
    JSON.stringify({
      version: 1,
      [kind]: Array.from({ length: kind === "exclude" ? 200 : 100 }, (_, i) => {
        const letter = String.fromCharCode(98 + (i % 25));
        return `*${"?".repeat(Math.floor(i / 25))}${`?${letter}`.repeat(60)}*`;
      }),
    });
  const manyFiles = (): Record<string, string> =>
    Object.fromEntries(
      Array.from({ length: 4000 }, (_, i) => [
        `src/p${i % 30}/${"a".repeat(24)}${i}.ts`,
        "export {};\n",
      ]),
    );

  it.each(["exclude", "testDirectories"] as const)(
    "%s patterns that exceed the budget warn, and later files are scanned, not dropped",
    async (kind) => {
      const root = project({
        ...manyFiles(),
        "pgard.config.json": hostile(kind),
        "zz/vuln.ts": SQL_VULN,
      });
      const result = await scan(root, ["code"]);
      const config = result.coverage.filter((entry) => entry.area === "source:config");
      expect(config).toHaveLength(1); // merged into one entry
      expect(config[0]?.status).toBe("partial");
      expect(config[0]?.note).toContain("exceeded the matching work limit");
      expect(result.overallStatus).toBe("partial");
      const area = result.coverage.find(
        (entry) => entry.area === `source:config-${kind === "exclude" ? "excluded" : "test"}`,
      );
      expect(area?.status).toBe("partial");
      expect(area?.note).toContain("work limit");
      // Fail-safe: the vulnerable file is analyzed and reported as regular code.
      const vuln = result.findings.find((f) => f.location.path === "zz/vuln.ts");
      expect(vuln).toBeDefined();
      expect(vuln?.context).toBeUndefined();
      expect(projectConfigNotices(result.coverage).some((n) => n.kind === "config")).toBe(true);
    },
    60_000,
  );
});

describe("runScan applies suppressions", () => {
  const cfg = (suppressions: unknown[], extra = "") =>
    JSON.stringify({ version: 1, suppressions }) + extra;
  const sup = (path: string, extra: Record<string, unknown> = {}) => ({
    ruleId: "PG-SQL-001",
    path,
    reason: "Admin-only script",
    ...extra,
  });

  it("keeps the finding, marks it, counts it and leaves status, coverage and exit untouched", async () => {
    const plain = await scan(project(SOURCES));
    const root = project({
      ...SOURCES,
      "pgard.config.json": cfg([sup("legacy/**")]),
    });
    const result = await scan(root);
    expect(result.findings).toHaveLength(3);
    const byPath = Object.fromEntries(result.findings.map((f) => [f.location.path, f]));
    expect(byPath["legacy/old.ts"]?.suppression).toEqual({
      reason: "Admin-only script",
      source: "pgard.config.json",
    });
    expect(byPath["src/db.ts"]?.suppression).toBeUndefined();
    expect(result.suppressions).toMatchObject({ suppressed: 1, critical: 0, incomplete: false });
    expect(coverageOf(result, "source:config")?.note).toContain(
      "1 suppression (1 finding suppressed (1 high), WARNING: 1 suppressed finding is high or critical)",
    );
    expect(coverageOf(result, "source:config")?.note).not.toContain("not yet applied");
    expect(result.overallStatus).toBe(plain.overallStatus);
    expect(result.authorization).toEqual(plain.authorization);
    expect(readScanResult(JSON.parse(JSON.stringify(result))).ok).toBe(true);
  });

  it("a config that suppresses everything leaves every finding in the result, flagged", async () => {
    const root = project({
      ...SOURCES,
      "pgard.config.json": cfg([sup("**", { reason: "nothing to see" })]),
    });
    const result = await scan(root);
    expect(result.findings).toHaveLength(3);
    expect(result.findings.every((f) => f.suppression?.reason === "nothing to see")).toBe(true);
    expect(result.suppressions?.entries[0]?.wildcard).toBe(true);
    expect(result.suppressions?.suppressed).toBe(3);
    // The status depends on coverage, not on findings.
    expect(result.overallStatus).toBe((await scan(project(SOURCES))).overallStatus);
  });

  it("does not apply an expired entry and keeps it in the summary", async () => {
    const root = project({
      ...SOURCES,
      "pgard.config.json": cfg([sup("legacy/**", { expires: "2026-10-26" })]),
    });
    const result = await scan(root);
    expect(result.findings.every((f) => f.suppression === undefined)).toBe(true);
    expect(result.suppressions?.entries[0]).toMatchObject({ state: "expired", matched: 0 });
    expect(coverageOf(result, "source:config")?.note).toContain("1 expired, not applied");
  });

  it("an invalid config applies no suppression at all", async () => {
    const root = project({
      ...SOURCES,
      "pgard.config.json": cfg([sup("**")], "").replace("}", ',"hosts":["x"]}'),
    });
    const result = await scan(root);
    expect(result.findings.every((f) => f.suppression === undefined)).toBe(true);
    expect(result.suppressions).toBeUndefined();
  });

  it("has no suppressions field without a config", async () => {
    expect((await scan(project(SOURCES))).suppressions).toBeUndefined();
  });

  it("applies to history findings as well, by their file path", async () => {
    const root = project({
      ...SOURCES,
      "pgard.config.json": cfg([sup("legacy/**")]),
    });
    const result = await scan(root, ["code", "history"]);
    expect(result.findings.filter((f) => f.suppression !== undefined)).toHaveLength(1);
  });
});

describe("suppressions never turn a partial scan into a completed one", () => {
  it("stays partial with every finding suppressed, and the coverage statuses are untouched", async () => {
    const files = { ...SOURCES };
    const plainRoot = project(files);
    const plain = await scan(plainRoot, ["code", "web"]);
    expect(plain.overallStatus).toBe("partial");
    const root = project({
      ...files,
      "pgard.config.json": JSON.stringify({
        version: 1,
        suppressions: [
          { ruleId: "PG-SQL-001", path: "**", reason: "all good", expires: "2026-12-31" },
        ],
      }),
    });
    const result = await scan(root, ["code", "web"]);
    expect(result.overallStatus).toBe("partial");
    expect(result.findings.every((f) => f.suppression !== undefined)).toBe(true);
    const statuses = (r: typeof result) =>
      r.coverage.filter((c) => c.area !== "source:config").map((c) => [c.area, c.status]);
    expect(statuses(result)).toEqual(statuses(plain));
    expect(coverageOf(result, "source:config")?.note).toContain("(3 high)");
  });
});
