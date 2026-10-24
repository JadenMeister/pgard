import { describe, expect, it } from "vitest";
import type { Finding } from "./contract.js";
import {
  applyFindingContext,
  isTestOrFixturePath,
  splitFindingsByContext,
} from "./finding-context.js";

function finding(path: string | null, overrides: Partial<Finding> = {}): Finding {
  return {
    id: "f1",
    ruleId: "PG-SECRET-002",
    title: "Secret in a tracked file",
    category: "secret_exposure",
    severity: "high",
    status: "suspected",
    confidence: "medium",
    location: { kind: "file", path, line: 3, url: null, commit: null },
    evidence: "credential assignment in a tracked file (value redacted)",
    impact: "i",
    recommendation: "r",
    references: { cwe: [], owasp: [], cve: [] },
    sources: ["history"],
    ...overrides,
  };
}

describe("isTestOrFixturePath", () => {
  it.each([
    "packages/findings/src/redact.test.ts",
    "src/app.spec.js",
    "src/App.test.tsx",
    "cmd/server/main_test.go",
    "src/__tests__/util.ts",
    "src/__mocks__/fs.ts",
    "src/__fixtures__/data.json",
    "test/helpers.js",
    "tests/e2e/login.py",
    "spec/fixtures/key.pem",
    "internal/parser/testdata/input.txt",
    "Tests/Unit/AppTests.swift",
  ])("classifies %s as test or fixture code", (path) => {
    expect(isTestOrFixturePath(path)).toBe(true);
  });

  it.each([
    "src/db.ts",
    "packages/scanner/src/secret-patterns.ts",
    "src/testing.ts",
    "src/contest/entry.ts",
    "src/latest.ts",
    "src/test.ts",
    "src/fixtures.ts",
    "src/attestation/tests.go",
    "package-lock.json",
    ".env",
    "",
  ])("keeps %s as regular code", (path) => {
    expect(isTestOrFixturePath(path)).toBe(false);
  });

  it("does not classify a missing path", () => {
    expect(isTestOrFixturePath(null)).toBe(false);
  });
});

describe("applyFindingContext", () => {
  it("marks test findings and caps confidence at low, keeping rule, severity and evidence", () => {
    const original = finding("src/__tests__/a.ts", { severity: "critical", confidence: "high" });
    expect(applyFindingContext(original)).toEqual({
      ...original,
      context: "test",
      confidence: "low",
    });
  });

  it("leaves regular findings unchanged", () => {
    const original = finding("src/a.ts");
    expect(applyFindingContext(original)).toBe(original);
  });

  it("leaves URL findings unchanged", () => {
    const original = finding(null, {
      location: {
        kind: "url",
        path: null,
        line: null,
        url: "http://127.0.0.1:3000/test/",
        commit: null,
      },
    });
    expect(applyFindingContext(original)).toBe(original);
  });
});

describe("splitFindingsByContext", () => {
  it("separates test findings without dropping any", () => {
    const regular = finding("src/a.ts");
    const test = applyFindingContext(finding("src/a.test.ts"));
    expect(splitFindingsByContext([test, regular])).toEqual({ primary: [regular], test: [test] });
  });
});
