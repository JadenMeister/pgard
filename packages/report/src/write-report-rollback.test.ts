import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Creating a PDF fails (a full disk, say) while HTML files can still be created.
vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    open: (async (...args: Parameters<typeof actual.open>) => {
      if (String(args[0]).endsWith(".pdf")) {
        throw Object.assign(new Error("no space"), { code: "ENOSPC" });
      }
      return actual.open(...args);
    }) as typeof actual.open,
  };
});

const { scanResult } = await import("./test-fixtures.js");
const { ReportWriteError, writeReports } = await import("./write-report.js");

describe("writeReports rollback", () => {
  let directory: string;
  beforeEach(async () => {
    directory = await mkdtemp(path.join(os.tmpdir(), "pgard-report-rollback-"));
  });
  afterEach(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  it("never deletes a skipped file when a later write fails", async () => {
    const [first] = await writeReports(scanResult(), { format: "html", outputDir: directory });
    const saved = first?.filePath ?? "";
    const error = await writeReports(scanResult(), {
      format: "both",
      outputDir: directory,
      skipExisting: new Set([saved]),
    }).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ReportWriteError);
    expect((error as InstanceType<typeof ReportWriteError>).code).toBe("write_failed");
    expect(await readFile(saved, "utf8")).toContain("PGARD security report");
    expect(await readdir(directory)).toHaveLength(1);
  });

  it("removes a file this call created when a later write fails", async () => {
    const error = await writeReports(scanResult(), { format: "both", outputDir: directory }).catch(
      (caught: unknown) => caught,
    );
    expect((error as InstanceType<typeof ReportWriteError>).code).toBe("write_failed");
    expect(await readdir(directory)).toEqual([]);
  });
});
