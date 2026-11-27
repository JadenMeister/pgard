import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { HISTORY_RULES } from "@pgard/git-history";
import { listSourceRules } from "@pgard/source-analysis";
import { describe, expect, it } from "vitest";
import { FAMILIES, familiesForCwes, IN_SCOPE_CWES, ruleInFamily } from "./cwe-families.mjs";
import { validRepo, validSha } from "./lib.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const read = (name: string) => JSON.parse(readFileSync(path.join(here, name), "utf8"));
interface Case {
  id: string;
  repo: string;
  fixCommit: string;
  vulnCommit: string;
  cwe: string[];
  doubtful: boolean;
  inScope: boolean;
  expect: { file: string; startLine: number; endLine: number }[];
}
const cases: Case[] = read("cases.json");
const doubtful: Record<string, string> = read("doubtful.json");

describe("cases.json integrity", () => {
  it("has unique ids, valid repos and 40-hex commits", () => {
    expect(new Set(cases.map((c) => c.id)).size).toBe(cases.length);
    for (const c of cases) {
      expect(validRepo(c.repo), c.id).toBe(true);
      expect(validSha(c.vulnCommit), `${c.id} vulnCommit`).toBe(true);
      expect(validSha(c.fixCommit), `${c.id} fixCommit`).toBe(true);
    }
  });

  it("has relative expected files without .. and ordered 1-based line ranges", () => {
    for (const c of cases) {
      expect(c.expect.length, c.id).toBeGreaterThan(0);
      for (const range of c.expect) {
        expect(range.file.startsWith("/") || /^[A-Za-z]:/.test(range.file), c.id).toBe(false);
        expect(range.file.split(/[\\/]/).includes(".."), c.id).toBe(false);
        expect(range.startLine, c.id).toBeGreaterThanOrEqual(1);
        expect(range.endLine, c.id).toBeGreaterThanOrEqual(range.startLine);
      }
    }
  });

  it("takes doubtful from doubtful.json (known ids, a reason each) and inScope from the map", () => {
    const ids = new Set(cases.map((c) => c.id));
    for (const [id, reason] of Object.entries(doubtful)) {
      expect(ids.has(id), id).toBe(true);
      expect(reason.length, id).toBeGreaterThan(0);
    }
    for (const c of cases) {
      expect(c.doubtful, c.id).toBe(c.id in doubtful);
      expect(c.inScope, c.id).toBe(familiesForCwes(c.cwe).length > 0);
    }
  });
});

describe("CWE to rule map", () => {
  const rules = [
    ...listSourceRules().map((r) => ({ id: r.id, cwe: r.cwe })),
    ...HISTORY_RULES.map((r) => ({ id: r.id, cwe: r.cwe })),
  ];

  it("lists every mapped CWE in the standards of a rule of its entry", () => {
    for (const entry of FAMILIES) {
      const entryRules = rules.filter((r) => ruleInFamily(r.id, entry));
      expect(entryRules.length, entry.prefixes.join()).toBeGreaterThan(0);
      for (const cwe of entry.cwes) {
        expect(
          entryRules.some((r) => r.cwe.includes(`CWE-${cwe}`)),
          `CWE-${cwe} in ${entry.prefixes.join()}`,
        ).toBe(true);
      }
    }
  });

  it("keeps assumed CWEs out of the rules' standards (move them if a rule lists them)", () => {
    for (const entry of FAMILIES) {
      for (const cwe of entry.assumed ?? []) {
        expect(
          rules.some((r) => r.cwe.includes(`CWE-${cwe}`)),
          `CWE-${cwe}`,
        ).toBe(false);
      }
    }
  });

  it("has no rule for authentication or configuration CWEs", () => {
    for (const cwe of [287, 306, 16, 1188, 326]) expect(IN_SCOPE_CWES).not.toContain(cwe);
  });
});
