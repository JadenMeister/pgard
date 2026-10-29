import { describe, expect, it } from "vitest";
import type { ReducedAdvisory } from "../osv/reduce.js";
import { cvss3BaseScore, advisorySeverity, severityFromScore } from "./severity.js";
import { evaluateAffected } from "./range.js";
import { versionScheme } from "./version.js";

const npm = versionScheme("npm")!;
const go = versionScheme("Go")!;

function verdict(
  scheme: NonNullable<ReturnType<typeof versionScheme>>,
  version: string,
  events: Record<string, string>[],
  type = "SEMVER",
) {
  const installed = scheme.parse(version);
  if (installed === null) throw new Error(`unparseable ${version}`);
  return evaluateAffected({ name: "x", ranges: [{ type, events }] }, installed, scheme);
}

describe("version schemes", () => {
  it("parses semver and rejects what is not semver", () => {
    expect(npm.parse("1.2.3")).not.toBeNull();
    expect(npm.parse("1.2.3-beta.1+build.5")).not.toBeNull();
    for (const bad of ["1.2", "1.2.3.4", "v1.2.3", "01.2.3", "1.2.3-", "latest", "", "1.2.3-01"]) {
      expect(npm.parse(bad), bad).toBeNull();
    }
  });

  it("orders pre-releases by the semver rules", () => {
    const order = [
      "1.0.0-alpha",
      "1.0.0-alpha.1",
      "1.0.0-alpha.beta",
      "1.0.0-beta",
      "1.0.0-beta.2",
      "1.0.0-beta.11",
      "1.0.0-rc.1",
      "1.0.0",
    ];
    for (let index = 1; index < order.length; index += 1) {
      const a = npm.parse(order[index - 1]!)!;
      const b = npm.parse(order[index]!)!;
      expect(npm.compare(a, b), `${order[index - 1]} < ${order[index]}`).toBeLessThan(0);
      expect(npm.compare(b, a)).toBeGreaterThan(0);
    }
    expect(npm.compare(npm.parse("1.0.0+a")!, npm.parse("1.0.0+b")!)).toBe(0);
    expect(npm.compare(npm.parse("10.0.0")!, npm.parse("9.0.0")!)).toBeGreaterThan(0);
  });

  it("reads Go module versions with a v prefix, +incompatible and pseudo-versions", () => {
    expect(go.parse("v1.2.3")).not.toBeNull();
    expect(go.parse("v2.0.0+incompatible")).not.toBeNull();
    const pseudo = go.parse("v0.0.0-20200101000000-abcdef123456")!;
    expect(go.compare(pseudo, go.parse("v0.0.0")!)).toBeLessThan(0);
    expect(go.compare(go.parse("v1.10.0")!, go.parse("v1.9.0")!)).toBeGreaterThan(0);
  });

  it("has no scheme for an ecosystem PGARD does not read", () => {
    for (const name of ["PyPI", "Maven", "Packagist", "crates.io"]) {
      expect(versionScheme(name)).toBeNull();
    }
  });
});

describe("OSV range evaluation", () => {
  const fixedAt = [{ introduced: "0" }, { fixed: "1.2.3" }];

  it("treats fixed as exclusive and introduced as inclusive (range edges)", () => {
    expect(verdict(npm, "1.2.2", fixedAt).verdict).toBe("affected");
    expect(verdict(npm, "1.2.3", fixedAt).verdict).toBe("not-affected");
    const window = [{ introduced: "1.0.0" }, { fixed: "1.2.3" }];
    expect(verdict(npm, "0.9.9", window).verdict).toBe("not-affected");
    expect(verdict(npm, "1.0.0", window).verdict).toBe("affected");
  });

  it("treats last_affected as inclusive", () => {
    const events = [{ introduced: "0" }, { last_affected: "2.0.0" }];
    expect(verdict(npm, "2.0.0", events).verdict).toBe("affected");
    expect(verdict(npm, "2.0.1", events).verdict).toBe("not-affected");
  });

  it("handles a pre-release below the fix", () => {
    const result = verdict(npm, "1.2.3-rc.1", fixedAt);
    expect(result.verdict).toBe("affected");
    expect(
      verdict(npm, "1.0.0-beta.1", [{ introduced: "1.0.0" }, { fixed: "2.0.0" }]).verdict,
    ).toBe("not-affected");
  });

  it("reports the range and the fixed versions newer than the installed one", () => {
    const result = verdict(npm, "1.5.0", [
      { introduced: "0" },
      { fixed: "1.2.3" },
      { introduced: "1.4.0" },
      { fixed: "1.6.1" },
      { introduced: "2.0.0" },
      { fixed: "2.1.0" },
    ]);
    expect(result).toMatchObject({
      verdict: "affected",
      range: ">=1.4.0 <1.6.1",
      fixed: ["1.6.1", "2.1.0"],
    });
  });

  it("matches an exact entry of the versions list", () => {
    const installed = npm.parse("3.1.0")!;
    expect(
      evaluateAffected({ name: "x", versions: ["3.0.0", "3.1.0"] }, installed, npm),
    ).toMatchObject({ verdict: "affected", via: "version-list" });
    expect(evaluateAffected({ name: "x", versions: ["3.0.0"] }, installed, npm).verdict).toBe(
      "not-affected",
    );
  });

  it("ignores GIT ranges and says unknown for a boundary it cannot read", () => {
    expect(
      verdict(npm, "1.0.0", [{ introduced: "abcdef0123" }, { fixed: "fedcba9876" }], "GIT").verdict,
    ).toBe("not-affected");
    expect(verdict(npm, "1.0.0", [{ introduced: "0" }, { fixed: "1.x" }]).verdict).toBe("unknown");
  });

  it("works for Go versions as OSV writes them (no v prefix)", () => {
    expect(verdict(go, "v1.4.0", [{ introduced: "0" }, { fixed: "1.4.1" }]).verdict).toBe(
      "affected",
    );
    expect(verdict(go, "v1.4.1", [{ introduced: "0" }, { fixed: "1.4.1" }]).verdict).toBe(
      "not-affected",
    );
  });
});

describe("severity", () => {
  it("computes CVSS v3 base scores", () => {
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBe(9.8);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")).toBe(7.5);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")).toBe(6.1);
    expect(cvss3BaseScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")).toBe(0);
    expect(cvss3BaseScore("CVSS:3.1/AV:N")).toBeNull();
    expect(cvss3BaseScore("garbage")).toBeNull();
    expect(
      cvss3BaseScore("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"),
    ).toBeNull();
  });

  it("maps scores to levels", () => {
    expect([9.8, 7.5, 5, 0.1, 0].map(severityFromScore)).toEqual([
      "critical",
      "high",
      "medium",
      "low",
      "info",
    ]);
  });

  it("prefers CVSS, then the database label, then unknown", () => {
    const base: ReducedAdvisory = { id: "A", modified: "x", affected: [] };
    expect(
      advisorySeverity({
        ...base,
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
        label: "LOW",
      }),
    ).toMatchObject({ level: "critical", source: "cvss", score: 9.8 });
    expect(advisorySeverity({ ...base, label: "MODERATE" })).toMatchObject({
      level: "medium",
      source: "database",
    });
    expect(
      advisorySeverity({
        ...base,
        severity: [{ type: "CVSS_V4", score: "CVSS:4.0/AV:N" }],
        label: "HIGH",
      }),
    ).toMatchObject({ level: "high", source: "database", vector: "CVSS:4.0/AV:N" });
    expect(advisorySeverity(base)).toEqual({ level: null, source: "unknown" });
  });
});
