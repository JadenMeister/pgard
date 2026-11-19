import { CERT_JAVA_RULES, CWE_TOP25, OWASP_TOP10_2025, certJavaUrl, cweUrl } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import { displayWidth } from "../i18n/display-width.js";
import { fitLine } from "./fit-lines.js";

const WIDTH = 40;

describe("fitLine links (#311)", () => {
  it("keeps every link PGARD writes whole, even past the width", () => {
    const urls = [
      ...OWASP_TOP10_2025.map((category) => category.url),
      ...CWE_TOP25.map((entry) => entry.url),
      cweUrl("CWE-89"),
      ...CERT_JAVA_RULES.map((rule) => certJavaUrl(rule)),
    ];
    expect(urls.length).toBeGreaterThan(50);
    for (const url of urls) {
      expect(fitLine(`  See ${url}`, WIDTH).join(" ")).toContain(url);
    }
  });

  it("shortens a long URL on a standards host that is not one of PGARD's link shapes", () => {
    const hostile = [
      `https://cwe.mitre.org/${"C".repeat(500)}`,
      `https://top10.owasp.org/2025/${"x".repeat(500)}`,
      `https://cwe.mitre.org/data/definitions/${"1".repeat(300)}.html`,
      `https://cmu-sei.github.io/${"a".repeat(500)}`,
    ];
    for (const url of hostile) {
      const lines = fitLine(`  See ${url}`, WIDTH);
      for (const line of lines) expect(displayWidth(line)).toBeLessThanOrEqual(WIDTH * 2);
      expect(lines.join("")).toContain("...");
    }
  });
});
