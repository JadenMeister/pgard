import {
  mkdtemp,
  mkdir,
  readdir,
  readFile,
  realpath,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { scanResult } from "./test-fixtures.js";
import { isPathInsideDirectory, ReportWriteError, writeReports } from "./write-report.js";

describe("writeReports", () => {
  let directory: string;
  beforeEach(async () => {
    directory = await mkdtemp(path.join(os.tmpdir(), "pgard-report-test-"));
  });
  afterEach(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  it("writes both formats into the given directory", async () => {
    const written = await writeReports(scanResult(), { format: "both", outputDir: directory });
    expect(written.map((entry) => entry.format)).toEqual(["html", "pdf"]);
    for (const entry of written) {
      expect(path.dirname(entry.filePath)).toBe(await realpath(directory));
      expect(path.basename(entry.filePath)).toMatch(
        /^pgard-report-20261024010203-3f2b9c1e\.(html|pdf)$/,
      );
    }
    expect(await readFile(written[0]!.filePath, "utf8")).toContain("PGARD security report");
  });

  it("never overwrites an existing file", async () => {
    await writeReports(scanResult(), { format: "html", outputDir: directory });
    const error = await writeReports(scanResult(), { format: "html", outputDir: directory }).catch(
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(ReportWriteError);
    expect((error as ReportWriteError).code).toBe("file_exists");
    expect(path.basename((error as ReportWriteError).path ?? "")).toMatch(/\.html$/);
  });

  it("does not follow a pre-planted symlink at the target name", async () => {
    const victim = path.join(directory, "victim.txt");
    await writeFile(victim, "original");
    await symlink(victim, path.join(directory, "pgard-report-20261024010203-3f2b9c1e.html"));
    await expect(
      writeReports(scanResult(), { format: "html", outputDir: directory }),
    ).rejects.toThrow(ReportWriteError);
    expect(await readFile(victim, "utf8")).toBe("original");
  });

  it("refuses a missing directory instead of creating it", async () => {
    const error = await writeReports(scanResult(), {
      format: "pdf",
      outputDir: path.join(directory, "missing"),
    }).catch((caught: unknown) => caught);
    expect((error as ReportWriteError).code).toBe("output_dir_missing");
  });

  it("refuses a file path as output directory", async () => {
    const file = path.join(directory, "file");
    await writeFile(file, "");
    const error = await writeReports(scanResult(), { format: "pdf", outputDir: file }).catch(
      (caught: unknown) => caught,
    );
    expect((error as ReportWriteError).code).toBe("output_dir_not_directory");
  });
});

describe("isPathInsideDirectory", () => {
  it("detects paths inside a repository, including via symlinks", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "pgard-inside-"));
    try {
      const repo = path.join(root, "repo");
      await mkdir(path.join(repo, "reports"), { recursive: true });
      await symlink(path.join(repo, "reports"), path.join(root, "link"));
      expect(await isPathInsideDirectory(path.join(repo, "reports"), repo)).toBe(true);
      expect(await isPathInsideDirectory(repo, repo)).toBe(true);
      expect(await isPathInsideDirectory(path.join(root, "link"), repo)).toBe(true);
      expect(await isPathInsideDirectory(path.join(repo, "not-yet", "deeper"), repo)).toBe(true);
      expect(await isPathInsideDirectory(root, repo)).toBe(false);
      expect(await isPathInsideDirectory(`${repo}-other`, repo)).toBe(false);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("writeReports atomicity", () => {
  let directory: string;
  beforeEach(async () => {
    directory = await mkdtemp(path.join(os.tmpdir(), "pgard-report-atomic-"));
  });
  afterEach(async () => {
    await rm(directory, { recursive: true, force: true });
  });

  it("writes nothing when the second target already exists", async () => {
    const pdfPath = path.join(directory, "pgard-report-20261024010203-3f2b9c1e.pdf");
    await writeFile(pdfPath, "existing");
    const error = await writeReports(scanResult(), { format: "both", outputDir: directory }).catch(
      (caught: unknown) => caught,
    );
    expect((error as ReportWriteError).code).toBe("file_exists");
    expect(path.basename((error as ReportWriteError).path ?? "")).toBe(path.basename(pdfPath));
    expect(await readdir(directory)).toEqual(["pgard-report-20261024010203-3f2b9c1e.pdf"]);
    expect(await readFile(pdfPath, "utf8")).toBe("existing");
  });

  it("reports render failures as ReportWriteError and writes nothing", async () => {
    const broken = scanResult({ findings: null as never });
    const error = await writeReports(broken, { format: "both", outputDir: directory }).catch(
      (caught: unknown) => caught,
    );
    expect(error).toBeInstanceOf(ReportWriteError);
    expect((error as ReportWriteError).code).toBe("render_failed");
    expect(await readdir(directory)).toEqual([]);
  });
});
