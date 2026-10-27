import { afterAll, describe, expect, it } from "vitest";
import { listFixtures, runFixtures } from "../test-support/fixtures.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzeJvmTree } from "./analyze-jvm.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

describe("injection fixtures (#205 layout)", () => {
  for (const language of ["java", "kotlin"] as const) {
    it(`flags every vulnerable ${language} fixture and no safe one`, async () => {
      const cases = listFixtures({ language, category: "injection" });
      expect(cases.length).toBeGreaterThanOrEqual(4);
      const report = await runFixtures(cases, async (fixture, source) => {
        const outcome = await runtime.parse(language, source);
        if (outcome.status !== "parsed") throw new Error(outcome.status);
        try {
          return analyzeJvmTree(outcome.tree.rootNode, source, fixture.name, language).findings
            .length;
        } finally {
          outcome.dispose();
        }
      });
      expect(report.missed.map((fixture) => fixture.relativePath)).toEqual([]);
      expect(report.falsePositives.map((fixture) => fixture.relativePath)).toEqual([]);
      expect(report.truePositives).toBeGreaterThanOrEqual(2);
    });
  }
});
