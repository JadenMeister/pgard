import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanDependencies } from "./scan.js";
import { advisory, writeOsvFixture } from "./test-support/osv-fixture.js";

let root: string;
let data: string;
const NOW = Date.parse("2026-10-29T00:00:00Z");
const FRESH = "2026-10-28T00:00:00Z";

beforeEach(async () => {
  root = await mkdtemp(path.join(os.tmpdir(), "pgard-depscan-"));
  data = await mkdtemp(path.join(os.tmpdir(), "pgard-depdata-"));
});
afterEach(async () => {
  await rm(root, { recursive: true, force: true });
  await rm(data, { recursive: true, force: true });
});

async function put(relative: string, content: string): Promise<void> {
  const file = path.join(root, relative);
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, content);
}

const npmLock = (packages: Record<string, { version: string; dev?: boolean }>): string =>
  JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { dependencies: { lodash: "*" } },
      ...Object.fromEntries(
        Object.entries(packages).map(([name, value]) => [`node_modules/${name}`, value]),
      ),
    },
  });

const CVSS_HIGH = [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" }];
const scan = (extra = {}) => scanDependencies(root, { appDataDir: data, now: () => NOW, ...extra });

describe("scanDependencies", () => {
  it("reports an affected version with the advisory, aliases, fix and severity", async () => {
    await put("package-lock.json", npmLock({ lodash: { version: "4.17.11" } }));
    await writeOsvFixture(
      data,
      "npm",
      [
        advisory("GHSA-aaaa-bbbb-cccc", "lodash", [{ introduced: "0" }, { fixed: "4.17.21" }], {
          aliases: ["CVE-2021-0001"],
          severity: CVSS_HIGH,
          summary: "Prototype pollution",
        }),
        advisory("GHSA-fixed", "lodash", [{ introduced: "0" }, { fixed: "4.17.5" }]),
        advisory("GHSA-other", "other", [{ introduced: "0" }]),
      ],
      { fetchedAt: FRESH },
    );
    const out = await scan();
    expect(out.findings).toHaveLength(1);
    const finding = out.findings[0]!;
    expect(finding).toMatchObject({
      ruleId: "PG-DEP-001",
      severity: "high",
      status: "suspected",
      confidence: "medium",
      location: { kind: "file", path: "package-lock.json", line: null },
      references: { cve: ["CVE-2021-0001"], cwe: ["CWE-1395"], owasp: ["A03:2025"] },
      dependency: {
        ecosystem: "npm",
        name: "lodash",
        version: "4.17.11",
        advisoryId: "GHSA-aaaa-bbbb-cccc",
        aliases: ["CVE-2021-0001"],
        affectedRange: "<4.17.21",
        fixedVersions: ["4.17.21"],
        severitySource: "cvss",
        score: 7.5,
      },
    });
    expect(finding.evidence).toContain("affected version");
    expect(finding.evidence).toContain("reachability and exploitability were not checked");
    expect(finding.evidence).not.toMatch(/\bexploitable\b(?! were)/);
    const area = out.coverage.find((c) => c.area === "deps:npm")!;
    expect(area.status).toBe("completed");
    expect(area.note).toContain("downloaded 2026-10-28");
    expect(area.note).toContain("version ");
    expect(out.ruleStats[0]).toMatchObject({ area: "deps:npm", findings: 1 });
  });

  it("skips withdrawn advisories and counts them", async () => {
    await put("package-lock.json", npmLock({ lodash: { version: "1.0.0" } }));
    await writeOsvFixture(
      data,
      "npm",
      [advisory("GHSA-w", "lodash", [{ introduced: "0" }], { withdrawn: "2026-01-01T00:00:00Z" })],
      { fetchedAt: FRESH },
    );
    const out = await scan();
    expect(out.findings).toEqual([]);
    expect(out.coverage[0]?.note).toContain("1 withdrawn advisories were ignored");
  });

  it("labels development-only dependencies and lowers their confidence", async () => {
    await put("package-lock.json", npmLock({ lodash: { version: "1.0.0", dev: true } }));
    await writeOsvFixture(data, "npm", [advisory("GHSA-d", "lodash", [{ introduced: "0" }])], {
      fetchedAt: FRESH,
    });
    const finding = (await scan()).findings[0]!;
    expect(finding.confidence).toBe("low");
    expect(finding.dependency?.dev).toBe(true);
    expect(finding.evidence).toContain("development-only dependency");
    expect(finding.severity).toBe("medium");
    expect(finding.dependency?.severitySource).toBe("unknown");
  });

  it("merges a GHSA and a GO record of the same issue into one finding", async () => {
    await put("go.mod", "module m\n\ngo 1.22\n\nrequire example.com/x v1.4.0\n");
    await writeOsvFixture(
      data,
      "Go",
      [
        advisory("GO-2026-0001", "example.com/x", [{ introduced: "0" }, { fixed: "1.4.1" }], {
          aliases: ["CVE-2026-1", "GHSA-gggg-hhhh-iiii"],
        }),
        advisory(
          "GHSA-gggg-hhhh-iiii",
          "example.com/x",
          [{ introduced: "0" }, { fixed: "1.4.1" }],
          {
            aliases: ["CVE-2026-1"],
            label: "HIGH",
          },
        ),
      ],
      { fetchedAt: FRESH },
    );
    const out = await scan();
    expect(out.findings).toHaveLength(1);
    expect(out.findings[0]?.dependency).toMatchObject({
      advisoryId: "GHSA-gggg-hhhh-iiii",
      aliases: ["GO-2026-0001", "CVE-2026-1"],
      severitySource: "database",
    });
    expect(out.findings[0]?.severity).toBe("high");
    expect(out.coverage.find((c) => c.area === "deps:Go")?.status).toBe("completed");
  });

  it("keeps the fingerprint across rescans and data versions", async () => {
    await put("package-lock.json", npmLock({ lodash: { version: "1.0.0" } }));
    const advisories = [advisory("GHSA-s", "lodash", [{ introduced: "0" }, { fixed: "2.0.0" }])];
    await writeOsvFixture(data, "npm", advisories, { fetchedAt: FRESH });
    const first = (await scan()).findings[0]!;
    await writeOsvFixture(
      data,
      "npm",
      [
        { ...advisories[0]!, modified: "2026-10-27T00:00:00Z", summary: "reworded" },
        advisory("GHSA-new", "unrelated", [{ introduced: "0" }]),
      ],
      { fetchedAt: "2026-10-28T12:00:00Z" },
    );
    const second = (await scan()).findings[0]!;
    expect(second.id).toBe(first.id);
  });

  it("is not_tested with the update hint when no data was downloaded", async () => {
    await put("package-lock.json", npmLock({ lodash: { version: "1.0.0" } }));
    const out = await scan();
    expect(out.findings).toEqual([]);
    expect(out.coverage[0]).toMatchObject({ area: "deps:npm", status: "not_tested" });
    expect(out.coverage[0]?.note).toContain("pgard advisories update");
    expect(out.ruleStats).toEqual([]);
  });

  it("is not_tested when there is no data folder at all", async () => {
    await put("package-lock.json", npmLock({ lodash: { version: "1.0.0" } }));
    const out = await scan({ appDataDir: null });
    expect(out.coverage[0]?.status).toBe("not_tested");
  });

  it("is partial, with the age, when the data is stale", async () => {
    await put("package-lock.json", npmLock({ lodash: { version: "1.0.0" } }));
    await writeOsvFixture(data, "npm", [advisory("GHSA-s", "lodash", [{ introduced: "0" }])], {
      fetchedAt: "2026-10-01T00:00:00Z",
      modifiedMax: "2026-09-30T00:00:00Z",
    });
    const out = await scan();
    expect(out.findings).toHaveLength(1);
    const area = out.coverage[0]!;
    expect(area.status).toBe("partial");
    expect(area.note).toContain("stale");
    expect(area.note).toContain("28 day(s) ago");
  });

  it("treats data whose newest record is old as stale even if downloaded today", async () => {
    await put("package-lock.json", npmLock({ lodash: { version: "1.0.0" } }));
    await writeOsvFixture(data, "npm", [], {
      fetchedAt: FRESH,
      modifiedMax: "2026-08-01T00:00:00Z",
    });
    expect((await scan()).coverage[0]?.status).toBe("partial");
  });

  it("is not_tested when the stored file does not match its checksum", async () => {
    await put("package-lock.json", npmLock({ lodash: { version: "1.0.0" } }));
    await writeOsvFixture(data, "npm", [advisory("GHSA-s", "lodash", [{ introduced: "0" }])], {
      fetchedAt: FRESH,
      badChecksum: true,
    });
    const out = await scan();
    expect(out.findings).toEqual([]);
    expect(out.coverage[0]).toMatchObject({ status: "not_tested" });
  });

  it("makes the area partial for a malformed lockfile and for unknown versions", async () => {
    await put("a/package-lock.json", "{ broken");
    await put(
      "b/package-lock.json",
      npmLock({ weird: { version: "1.0" }, lodash: { version: "1.0.0" } }),
    );
    await writeOsvFixture(
      data,
      "npm",
      [
        advisory("GHSA-w", "weird", [{ introduced: "0" }]),
        advisory("GHSA-l", "lodash", [{ introduced: "0" }, { fixed: "1.0.1" }]),
      ],
      { fetchedAt: FRESH },
    );
    const out = await scan();
    expect(out.findings.map((f) => f.dependency?.name)).toEqual(["lodash"]);
    const area = out.coverage[0]!;
    expect(area.status).toBe("partial");
    expect(area.note).toContain("a/package-lock.json");
    expect(area.note).toContain("could not be compared");
    expect(area.note).toContain("weird@1.0");
  });

  it("reports lockfiles of other ecosystems in an area without rules", async () => {
    await put("poetry.lock", "[[package]]\n");
    const out = await scan();
    expect(out.coverage).toHaveLength(1);
    expect(out.coverage[0]).toMatchObject({
      area: "deps:unsupported",
      status: "partial",
      ruleIds: [],
    });
  });

  it("emits nothing for a project without lockfiles", async () => {
    await put("src/index.js", "x");
    expect(await scan()).toEqual({ findings: [], coverage: [], ruleStats: [] });
  });

  it("leaves out files the configuration excludes", async () => {
    await put("fixtures/package-lock.json", npmLock({ lodash: { version: "1.0.0" } }));
    await writeOsvFixture(data, "npm", [advisory("GHSA-s", "lodash", [{ introduced: "0" }])], {
      fetchedAt: FRESH,
    });
    const out = await scan({ isExcluded: (p: string) => p.startsWith("fixtures/") });
    expect(out.findings).toEqual([]);
    expect(out.coverage).toEqual([]);
  });

  it("rejects when cancelled", async () => {
    await put("package-lock.json", npmLock({ lodash: { version: "1.0.0" } }));
    const controller = new AbortController();
    controller.abort();
    await expect(scan({ signal: controller.signal })).rejects.toMatchObject({ name: "AbortError" });
  });
});
