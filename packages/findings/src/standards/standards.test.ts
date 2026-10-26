import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  CERT_JAVA_ID_PATTERN,
  CERT_JAVA_PROVENANCE,
  CERT_JAVA_RULES,
  CWE_ID_PATTERN,
  CWE_TOP25,
  CWE_TOP25_PROVENANCE,
  OWASP_ID_PATTERN,
  OWASP_TOP10_2025,
  OWASP_TOP10_2025_PROVENANCE,
  certJavaRulesForCwe,
  certJavaUrl,
  cweUrl,
  getCertJavaRule,
  getCweTop25Entry,
  getOwaspCategory,
  isCweTop25,
} from "./index.js";

const unique = (values: readonly string[]) => new Set(values).size === values.length;

describe("OWASP Top 10 2025 data", () => {
  it("has the 10 categories in order with unique, well-formed ids", () => {
    expect(OWASP_TOP10_2025.map((c) => c.id)).toEqual(
      Array.from({ length: 10 }, (_, i) => `A${String(i + 1).padStart(2, "0")}:2025`),
    );
    expect(unique(OWASP_TOP10_2025.map((c) => c.id))).toBe(true);
    for (const c of OWASP_TOP10_2025) {
      expect(c.id).toMatch(OWASP_ID_PATTERN);
      expect(c.title.length).toBeGreaterThan(0);
      expect(c.url).toMatch(/^https:\/\/top10\.owasp\.org\/2025\/A\d\d_2025-/);
    }
  });
});

describe("CWE Top 25 data", () => {
  it("has 25 unique, well-formed entries ranked 1..25", () => {
    expect(CWE_TOP25.map((c) => c.rank)).toEqual(Array.from({ length: 25 }, (_, i) => i + 1));
    expect(unique(CWE_TOP25.map((c) => c.id))).toBe(true);
    for (const c of CWE_TOP25) {
      expect(c.id).toMatch(CWE_ID_PATTERN);
      expect(c.name.length).toBeGreaterThan(0);
      expect(c.url).toBe(cweUrl(c.id));
    }
  });
});

describe("CERT Java data", () => {
  it("has unique, well-formed rule ids and non-empty titles", () => {
    expect(CERT_JAVA_RULES.length).toBeGreaterThan(150);
    expect(unique(CERT_JAVA_RULES.map((r) => r.id))).toBe(true);
    for (const r of CERT_JAVA_RULES) {
      expect(r.id).toMatch(CERT_JAVA_ID_PATTERN);
      expect(r.title.length).toBeGreaterThan(0);
      expect(r.path).toMatch(/^[a-z-]+\/[a-z]{3}\d{2}-j$/);
      expect(unique(r.cwe)).toBe(true);
      for (const cwe of r.cwe) expect(cwe).toMatch(CWE_ID_PATTERN);
    }
  });

  it("lists the stable anchor rules with their related CWE ids", () => {
    expect(getCertJavaRule("IDS00-J")?.title).toBe("Prevent SQL injection");
    expect(getCertJavaRule("IDS07-J")?.cwe).toContain("CWE-78");
    expect(getCertJavaRule("SER12-J")?.title).toBe("Prevent deserialization of untrusted data");
    expect(certJavaUrl(getCertJavaRule("IDS00-J")!)).toBe(
      "https://cmu-sei.github.io/secure-coding-standards/sei-cert-oracle-coding-standard-for-java/rules/input-validation-and-data-sanitization-ids/ids00-j",
    );
  });
});

describe("lookup API", () => {
  it("resolves known ids and returns undefined otherwise", () => {
    expect(getOwaspCategory("A05:2025")?.title).toBe("Injection");
    expect(getOwaspCategory("A09:2025")?.title).toBe("Security Logging & Alerting Failures");
    expect(getOwaspCategory("A03:2021")).toBeUndefined();
    expect(getCweTop25Entry("CWE-79")?.rank).toBe(1);
    expect(getCweTop25Entry("CWE-798")).toBeUndefined();
    expect(getCertJavaRule("NOPE00-J")).toBeUndefined();
  });

  it("tells Top 25 members from other CWE ids", () => {
    expect(isCweTop25("CWE-79")).toBe(true);
    expect(isCweTop25("CWE-770")).toBe(true);
    expect(isCweTop25("CWE-798")).toBe(false);
    expect(isCweTop25("CWE-1")).toBe(false);
  });

  it("returns exactly the CERT rules that list a CWE id", () => {
    expect(certJavaRulesForCwe("CWE-78").map((r) => r.id)).toEqual(["IDS07-J"]);
    expect(certJavaRulesForCwe("CWE-798").map((r) => r.id)).toEqual(["MSC03-J"]);
    expect(certJavaRulesForCwe("CWE-89")).toEqual([]);
    for (const rule of certJavaRulesForCwe("CWE-327")) expect(rule.cwe).toContain("CWE-327");
  });
});

describe("id patterns", () => {
  it("accepts well-formed ids only", () => {
    for (const id of ["CWE-1", "CWE-79", "CWE-1004"]) expect(id).toMatch(CWE_ID_PATTERN);
    for (const id of ["CWE-", "CWE-0", "CWE-01", "CWE-7a", "cwe-79", "79", " CWE-79"]) {
      expect(id).not.toMatch(CWE_ID_PATTERN);
    }
    for (const id of ["A01:2025", "A10:2025"]) expect(id).toMatch(OWASP_ID_PATTERN);
    for (const id of ["A00:2025", "A11:2025", "A05", "A05:2021", "A5:2025"]) {
      expect(id).not.toMatch(OWASP_ID_PATTERN);
    }
    for (const id of ["IDS00-J", "MSC11-J"]) expect(id).toMatch(CERT_JAVA_ID_PATTERN);
    for (const id of ["IDS0-J", "IDS00-K", "ids00-j", "IDS000-J", "IDS00-J "]) {
      expect(id).not.toMatch(CERT_JAVA_ID_PATTERN);
    }
  });
});

describe("generated CERT Java data", () => {
  it("matches the pinned hash of the generator output (commit 72e8a32)", () => {
    // Regenerate with packages/findings/scripts/generate-cert-java.mjs and update the hash on purpose.
    const digest = createHash("sha256").update(JSON.stringify(CERT_JAVA_RULES)).digest("hex");
    expect(CERT_JAVA_RULES).toHaveLength(177);
    expect(digest).toBe("c6463abcc1fcbb2697620d3e031dfc44da0147381e0f01385b51288c236340e5");
  });
});

describe("provenance", () => {
  it.each([CERT_JAVA_PROVENANCE, CWE_TOP25_PROVENANCE, OWASP_TOP10_2025_PROVENANCE])(
    "$name records source, edition, date and license",
    (p) => {
      expect(p.sourceUrl).toMatch(/^https:\/\//);
      expect(p.edition.length).toBeGreaterThan(0);
      expect(p.retrievedAt).toBe("2026-10-26");
      expect(p.license.length).toBeGreaterThan(0);
      expect(p.attribution.length).toBeGreaterThan(0);
    },
  );
});
