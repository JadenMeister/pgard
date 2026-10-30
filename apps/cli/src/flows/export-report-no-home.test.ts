import { describe, expect, it, vi } from "vitest";
import {
  createTestContext,
  createTestDeps,
  createTestIo,
  panelsFixtureResult,
  scriptedKeys,
} from "../test-support.js";

vi.mock("../home-dir.js", () => ({ codeOnlyHome: () => null }));

describe("report folder prompt without a known home", () => {
  it("has no default and tells the user to type a folder on Enter", async () => {
    const { runReportExport } = await import("./export-report.js");
    const captured = createTestIo({ isTTY: true });
    const context = createTestContext(
      captured,
      createTestDeps(),
      scriptedKeys(["down", "return", "return", "escape"]),
    );
    expect(await runReportExport(context, panelsFixtureResult(), "/work/repo")).toBe("cancelled");
    expect(captured.stdout()).toContain("Save to folder:");
    expect(captured.stdout()).toContain("Type a folder.");
  });
});
