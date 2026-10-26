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
    expect(getOwaspCategory("A03:2021")).toBeUndefined();
    expect(getCweTop25Entry("CWE-79")?.rank).toBe(1);
    expect(isCweTop25("CWE-798")).toBe(false);
    expect(certJavaRulesForCwe("CWE-78").map((r) => r.id)).toContain("IDS07-J");
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
