import type { Finding } from "@pgard/findings";
import { describe, expect, it } from "vitest";
import { takeTokenFromLocation, hasSessionToken } from "../../api/client";
import { isGitHubUrl } from "../../components/github/device-code";
import { countBySeverity, EMPTY_FILTERS, filterFindings, formatLocation } from "./filter-findings";

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "f",
    ruleId: "PG-SQL-001",
    title: "SQL",
    category: "injection",
    severity: "high",
    status: "suspected",
    confidence: "medium",
    location: { kind: "file", path: "src/a.ts", line: 3, url: null, commit: null },
    evidence: "",
    impact: "",
    recommendation: "",
    references: { cwe: [], owasp: [], cve: [] },
    sources: ["code"],
    ...overrides,
  };
}

const FINDINGS = [
  finding({
    id: "a",
    severity: "low",
    status: "informational",
    sources: ["web"],
    ruleId: "PG-WEB-001",
    location: { kind: "url", path: null, line: null, url: "http://127.0.0.1:3000/", commit: null },
  }),
  finding({
    id: "b",
    severity: "critical",
    status: "confirmed",
    ruleId: "PG-SECRET-001",
    sources: ["history"],
  }),
  finding({ id: "c" }),
];

describe("filterFindings", () => {
  it("sorts by severity and filters by severity, status, source and text", () => {
    expect(filterFindings(FINDINGS, EMPTY_FILTERS).map((entry) => entry.id)).toEqual([
      "b",
      "c",
      "a",
    ]);
    expect(
      filterFindings(FINDINGS, { ...EMPTY_FILTERS, severity: "low" }).map((entry) => entry.id),
    ).toEqual(["a"]);
    expect(
      filterFindings(FINDINGS, { ...EMPTY_FILTERS, source: "history" }).map((entry) => entry.id),
    ).toEqual(["b"]);
    expect(
      filterFindings(FINDINGS, { ...EMPTY_FILTERS, status: "suspected" }).map((entry) => entry.id),
    ).toEqual(["c"]);
    expect(
      filterFindings(FINDINGS, { ...EMPTY_FILTERS, text: "127.0.0.1" }).map((entry) => entry.id),
    ).toEqual(["a"]);
  });

  it("counts per severity and formats locations", () => {
    expect(countBySeverity(FINDINGS)).toEqual({ critical: 1, high: 1, medium: 0, low: 1, info: 0 });
    expect(formatLocation(FINDINGS[2]!.location)).toBe("src/a.ts:3");
    expect(formatLocation(FINDINGS[0]!.location)).toBe("http://127.0.0.1:3000/");
  });
});

describe("takeTokenFromLocation", () => {
  it("reads the token from the fragment and removes it from the address bar", () => {
    const replaced: string[] = [];
    const history = {
      replaceState: (_s: unknown, _t: string, url: string) => replaced.push(url),
    } as unknown as History;
    const location = {
      hash: "#token=abcdefghijklmnopqrstuvwxyz012345",
      pathname: "/",
      search: "",
    } as Location;
    expect(takeTokenFromLocation(location, history)).toBe("abcdefghijklmnopqrstuvwxyz012345");
    expect(hasSessionToken()).toBe(true);
    expect(replaced).toEqual(["/"]);
    expect(
      takeTokenFromLocation({ ...location, hash: "#token=<script>" } as Location, history),
    ).toBeNull();
  });
});

describe("isGitHubUrl", () => {
  it("only accepts https github.com links", () => {
    expect(isGitHubUrl("https://github.com/login/device")).toBe(true);
    expect(isGitHubUrl("javascript:alert(1)")).toBe(false);
    expect(isGitHubUrl("http://github.com/login/device")).toBe(false);
    expect(isGitHubUrl("https://github.com.evil.example/")).toBe(false);
  });
});
