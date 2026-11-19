import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";
import { runScanCommand } from "../commands/scan/index.js";
import {
  createTestContext,
  createTestDeps,
  createTestIo,
  panelsFixtureResult,
  scriptedKeys,
} from "../test-support.js";
import { runReportExport, saveReports } from "./export-report.js";

/** The set of reports one run saved is shared by `--report`, the panel's `e` and the menu question (#342). */
describe("saved-path set shared between report saves", () => {
  const outputDir = mkdtempSync(path.join(os.tmpdir(), "pgard-saved-set-"));
  afterAll(() => rmSync(outputDir, { recursive: true, force: true }));
  const saved = "/out/pgard-report-1.html";

  it("saveReports passes the set on, fills it and says so on a repeat", async () => {
    const captured = createTestIo();
    const writeReports = vi.fn(
      async (_result: unknown, options: { skipExisting?: Set<string> }) => [
        options.skipExisting?.has(saved) === true
          ? { format: "html" as const, filePath: saved, skipped: true as const }
          : { format: "html" as const, filePath: saved },
      ],
    );
    const context = createTestContext(
      captured,
      createTestDeps({ writeReports: writeReports as never }),
    );
    const set = new Set<string>();
    expect(await saveReports(context, panelsFixtureResult(), "html", outputDir, set)).toBe(true);
    expect(set.has(saved)).toBe(true);
    expect(captured.stdout()).toContain("Saved HTML report");
    expect(await saveReports(context, panelsFixtureResult(), "html", outputDir, set)).toBe(true);
    expect(writeReports.mock.calls[1]?.[1].skipExisting).toBe(set);
    expect(captured.stdout()).toContain("already saved");
  });

  it("without a set nothing is skipped or remembered", async () => {
    const captured = createTestIo();
    const writeReports = vi.fn(async (_result: unknown, _options: object) => [
      { format: "html" as const, filePath: saved },
    ]);
    const context = createTestContext(
      captured,
      createTestDeps({ writeReports: writeReports as never }),
    );
    await saveReports(context, panelsFixtureResult(), "html", outputDir);
    expect(writeReports.mock.calls[0]?.[1]).not.toHaveProperty("skipExisting");
  });

  it("the menu's report question gets the same set and treats a repeat as saved", async () => {
    const captured = createTestIo({ isTTY: true });
    const writeReports = vi.fn(
      async (_result: unknown, options: { skipExisting?: Set<string> }) => [
        options.skipExisting?.has(saved) === true
          ? { format: "html" as const, filePath: saved, skipped: true as const }
          : { format: "html" as const, filePath: saved },
      ],
    );
    const chars = Array.from(outputDir);
    const keys = scriptedKeys([
      "down",
      "return",
      ...chars,
      "return",
      "down",
      "return",
      ...chars,
      "return",
    ] as never[]);
    const context = createTestContext(
      captured,
      createTestDeps({ writeReports: writeReports as never }),
      keys,
      true,
    );
    const set = new Set<string>();
    expect(await runReportExport(context, panelsFixtureResult(), "/work/repo", set)).toBe("saved");
    expect(set.has(saved)).toBe(true);
    expect(await runReportExport(context, panelsFixtureResult(), "/work/repo", set)).toBe("saved");
    expect(writeReports.mock.calls[0]?.[1].skipExisting).toBe(set);
    expect(captured.stdout()).toContain("already saved");
  });

  it("the --report save of a scan run gets a set that it fills for the later questions", async () => {
    const captured = createTestIo();
    const sets: Array<Set<string>> = [];
    const writeReports = vi.fn(
      async (_result: unknown, options: { skipExisting?: Set<string> }) => {
        if (options.skipExisting !== undefined) sets.push(options.skipExisting);
        return [{ format: "html" as const, filePath: saved }];
      },
    );
    const context = createTestContext(
      captured,
      createTestDeps({
        runScan: async () => panelsFixtureResult(),
        writeReports: writeReports as never,
      }),
    );
    await runScanCommand(context, {
      variant: "code",
      port: null,
      report: { format: "html", outputDir },
      format: "json",
    });
    expect(sets).toHaveLength(1);
    expect(sets[0]?.has(saved)).toBe(true);
  });
});
