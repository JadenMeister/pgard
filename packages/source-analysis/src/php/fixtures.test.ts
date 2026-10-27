import { afterAll, describe, expect, it } from "vitest";
import { listFixtures, runFixtures } from "../test-support/fixtures.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzePhpTree } from "./analyze-php.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

describe("PHP fixtures (#205 layout)", () => {
  for (const category of ["injection", "command_execution"] as const) {
    it(`flags every vulnerable ${category} fixture and no safe one`, async () => {
      const cases = listFixtures({ language: "php", category });
      expect(cases.length).toBeGreaterThanOrEqual(6);
      const report = await runFixtures(cases, async (fixture, source) => {
        const outcome = await runtime.parse("php", source);
        if (outcome.status !== "parsed") throw new Error(outcome.status);
        try {
          return analyzePhpTree(outcome.tree.rootNode, source, fixture.name).findings.length;
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
