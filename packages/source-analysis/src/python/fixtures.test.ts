import { afterAll, describe, expect, it } from "vitest";
import type { FindingCategory } from "@pgard/findings";
import { listFixtures, runFixtures } from "../test-support/fixtures.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzePythonTree } from "./analyze-python.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

const RULE_OF: Record<string, string> = {
  injection: "PG-SQL-006",
  command_execution: "PG-CMD-004",
};

describe("Python fixtures (#205 layout)", () => {
  for (const category of Object.keys(RULE_OF) as FindingCategory[]) {
    it(`flags every vulnerable ${category} fixture and no safe one`, async () => {
      const cases = listFixtures({ language: "python", category });
      expect(cases.length).toBeGreaterThanOrEqual(6);
      const report = await runFixtures(cases, async (fixture, source) => {
        const outcome = await runtime.parse("python", source);
        if (outcome.status !== "parsed") throw new Error(outcome.status);
        try {
          return analyzePythonTree(outcome.tree.rootNode, source, fixture.name).findings.filter(
            (finding) => finding.ruleId === RULE_OF[category],
          ).length;
        } finally {
          outcome.dispose();
        }
      });
      expect(report.missed.map((fixture) => fixture.relativePath)).toEqual([]);
      expect(report.falsePositives.map((fixture) => fixture.relativePath)).toEqual([]);
      expect(report.truePositives).toBeGreaterThanOrEqual(3);
    });
  }
});
