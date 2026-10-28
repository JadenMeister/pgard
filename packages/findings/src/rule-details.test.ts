import { describe, expect, it } from "vitest";
import {
  buildRuleDetails,
  directCertIdsForPath,
  isJvmSourcePath,
  noDirectCertFor,
  resolveStandardLinks,
  standardsForFindings,
  standardsForPath,
} from "./rule-details.js";
import { buildRuleTextCatalog } from "./rule-text.js";
import type { RuleMetadata } from "./rule-metadata.js";

const metadata: RuleMetadata = {
  standards: {
    owasp: ["A05:2025"],
    cwe: ["CWE-89", "CWE-1004"],
    cert: [
      { kind: "direct", id: "IDS00-J" },
      { kind: "via-cwe", id: "IDS00-J", cwe: "CWE-89" },
    ],
  },
  rationale: { en: "why", ko: "이유" },
  remediation: { en: "fix", ko: "조치" },
  examples: [{ language: "go", vulnerable: "a", safe: "b", note: { en: "n", ko: "메모" } }],
};

describe("resolveStandardLinks", () => {
  it("links only official pages: OWASP site, MITRE CWE definitions, SEI CERT pages", () => {
    const links = resolveStandardLinks(metadata.standards);
    expect(links.map((link) => `${link.kind}:${link.id}`)).toEqual([
      "owasp:A05:2025",
      "cwe:CWE-89",
      "cwe:CWE-1004",
      "cert:IDS00-J",
      "cert:IDS00-J",
    ]);
    expect(links[0]).toMatchObject({
      title: "Injection",
      url: "https://top10.owasp.org/2025/A05_2025-Injection/",
    });
    expect(links[1]?.url).toBe("https://cwe.mitre.org/data/definitions/89.html");
    // Top 25 entries carry the CWE name; others only the id.
    expect(links[1]?.title).toContain("SQL");
    expect(links[2]?.title).toBeNull();
    expect(links[3]?.url).toMatch(/^https:\/\/cmu-sei\.github\.io\/secure-coding-standards\//);
    expect(links[3]?.viaCwe).toBeUndefined();
    expect(links[4]?.viaCwe).toBe("CWE-89");
  });

  it("skips ids the bundled data does not know", () => {
    expect(
      resolveStandardLinks({
        owasp: [],
        cwe: [],
        cert: [{ kind: "direct", id: "ZZZ99-J" }],
      }),
    ).toEqual([]);
  });
});

describe("rule details in the catalog", () => {
  it("copies the metadata so a consumer cannot change the rule", () => {
    const details = buildRuleDetails(metadata);
    details.rationale.en = "changed";
    expect(metadata.rationale.en).toBe("why");
    expect(details.examples[0]?.note?.ko).toBe("메모");
  });

  it("attaches details to every catalog entry", () => {
    const catalog = buildRuleTextCatalog([{ id: "R-1", title: "Rule", metadata }]);
    expect(catalog.get("R-1")?.details?.standards.length).toBe(5);
    expect(catalog.get("R-1")?.details?.remediation.ko).toBe("조치");
  });
});

describe("direct CERT links only for Java and Kotlin files", () => {
  const links = resolveStandardLinks(metadata.standards);
  const certOf = (path: string | null): string[] =>
    standardsForPath(links, path)
      .filter((link) => link.kind === "cert")
      .map((link) =>
        link.direct === true ? `${link.id} direct` : `${link.id} via ${link.viaCwe}`,
      );

  it("marks the direct link and keeps the indirect one", () => {
    expect(links.filter((l) => l.kind === "cert").map((l) => l.direct)).toEqual([true, undefined]);
  });

  it("shows a direct link on .java and .kt files, in place of the redundant indirect one", () => {
    expect(certOf("src/A.java")).toEqual(["IDS00-J direct"]);
    expect(certOf("app/src/Main.KT")).toEqual(["IDS00-J direct"]);
  });

  it("never shows a direct link on any other file, a missing path or a Gradle script", () => {
    for (const path of [
      "a.ts",
      "a.js",
      "a.go",
      "a.py",
      "a.php",
      "a.vue",
      "build.gradle.kts",
      null,
    ]) {
      expect(certOf(path), String(path)).toEqual(["IDS00-J via CWE-89"]);
    }
    // The input is not mutated.
    expect(links).toHaveLength(5);
  });

  it("decides per group of findings: direct for a JVM finding, indirect for the others", () => {
    const java = { location: { path: "A.java" } };
    const js = { location: { path: "a.js" } };
    const certs = (group: Array<{ location: { path: string | null } }>): string[] =>
      standardsForFindings(links, group)
        .filter((link) => link.kind === "cert")
        .map((link) => (link.direct === true ? "direct" : "via"));
    expect(certs([java])).toEqual(["direct"]);
    expect(certs([js])).toEqual(["via"]);
    expect(certs([java, js])).toEqual(["direct", "via"]);
  });

  it("derives the finding references from the metadata and the path", () => {
    expect(directCertIdsForPath(metadata.standards, "A.java")).toEqual(["IDS00-J"]);
    expect(directCertIdsForPath(metadata.standards, "a.ts")).toEqual([]);
    expect(directCertIdsForPath(metadata.standards, null)).toEqual([]);
    expect(isJvmSourcePath("x/Y.kt")).toBe(true);
    expect(isJvmSourcePath("x/Y.kts")).toBe(false);
  });

  it("carries the no-direct marker into the rule details", () => {
    const marked = buildRuleDetails({
      ...metadata,
      standards: {
        ...metadata.standards,
        cert: [],
        noDirectCert: { en: "None.", ko: "없음." },
      },
    });
    expect(marked.noDirectCert).toEqual({ en: "None.", ko: "없음." });
    expect(buildRuleDetails(metadata).noDirectCert).toBeUndefined();
  });
});

describe("direct CERT links scoped to a cause", () => {
  const links = resolveStandardLinks({
    owasp: [],
    cwe: ["CWE-327"],
    cert: [{ kind: "direct", id: "MSC02-J", cause: "weak-random" }],
  });
  const ids = (path: string | null, cert?: string[]): string[] =>
    standardsForPath(links, path, cert)
      .filter((l) => l.kind === "cert")
      .map((l) => l.id);

  it("carries the cause on the link", () => {
    expect(links.find((l) => l.kind === "cert")?.cause).toBe("weak-random");
  });

  it("shows the link only for a JVM finding whose references.cert names it", () => {
    expect(ids("A.java", ["MSC02-J"])).toEqual(["MSC02-J"]);
    expect(ids("A.java", [])).toEqual([]);
    expect(ids("A.java")).toEqual([]);
    expect(ids("a.ts", ["MSC02-J"])).toEqual([]);
  });

  it("decides a group per finding", () => {
    const withCert = { location: { path: "A.java" }, references: { cert: ["MSC02-J"] } };
    const without = { location: { path: "B.java" }, references: {} };
    const count = (group: Array<typeof withCert | typeof without>): number =>
      standardsForFindings(links, group).filter((l) => l.kind === "cert").length;
    expect(count([without])).toBe(0);
    expect(count([without, withCert])).toBe(1);
  });
});

describe("noDirectCertFor", () => {
  const other = { en: "Other.", ko: "기타." };
  const own = { en: "Own.", ko: "자체." };
  it("shows the rule's own marker on Java and Kotlin files only", () => {
    expect(noDirectCertFor({ noDirectCert: own }, "A.java")).toBe(own);
    expect(noDirectCertFor({ noDirectCert: own }, "a.ts")).toBeUndefined();
    expect(noDirectCertFor(undefined, "A.java")).toBeUndefined();
  });
  it("shows the other-causes marker only on a JVM finding without a CERT reference", () => {
    const details = { noDirectCertOther: other };
    expect(noDirectCertFor(details, "A.java", [])).toBe(other);
    expect(noDirectCertFor(details, "A.kt")).toBe(other);
    expect(noDirectCertFor(details, "A.java", ["MSC02-J"])).toBeUndefined();
    expect(noDirectCertFor(details, "a.ts", [])).toBeUndefined();
  });
});
