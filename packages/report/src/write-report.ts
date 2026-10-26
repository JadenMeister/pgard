import { lstat, open, realpath, stat, unlink } from "node:fs/promises";
import path from "node:path";
import type { ScanResult } from "@pgard/findings";
import { renderHtmlReport } from "./render-html.js";
import { renderPdfReport } from "./render-pdf.js";

export type ReportFormat = "html" | "pdf" | "both";
export const REPORT_FORMATS: readonly ReportFormat[] = ["html", "pdf", "both"];

export function isReportFormat(value: string): value is ReportFormat {
  return (REPORT_FORMATS as readonly string[]).includes(value);
}

export type ReportWriteErrorCode =
  | "output_dir_missing"
  | "output_dir_not_directory"
  | "file_exists"
  | "render_failed"
  | "write_failed";

export class ReportWriteError extends Error {
  readonly code: ReportWriteErrorCode;
  constructor(code: ReportWriteErrorCode, message: string) {
    super(message);
    this.name = "ReportWriteError";
    this.code = code;
  }
}

export interface WrittenReport {
  format: "html" | "pdf";
  filePath: string;
}

export interface WriteReportsOptions {
  format: ReportFormat;
  /** Directory chosen by the user. It must already exist; PGARD never creates or picks one. */
  outputDir: string;
}

/** Base file name: `pgard-report-<UTC timestamp>-<scan id prefix>`. */
export function buildReportBaseName(result: ScanResult): string {
  const stamp = result.startedAt.replace(/[^0-9]/g, "").slice(0, 14) || "unknown";
  const id = result.scanId.replace(/[^A-Za-z0-9]/g, "").slice(0, 8) || "scan";
  return `pgard-report-${stamp}-${id}`;
}

async function resolveOutputDir(outputDir: string): Promise<string> {
  const absolute = path.resolve(outputDir);
  let info;
  try {
    info = await stat(absolute);
  } catch {
    throw new ReportWriteError(
      "output_dir_missing",
      `Output directory does not exist: ${absolute}`,
    );
  }
  if (!info.isDirectory()) {
    throw new ReportWriteError(
      "output_dir_not_directory",
      `Output path is not a directory: ${absolute}`,
    );
  }
  return realpath(absolute);
}

/**
 * Writes with exclusive create (`wx`): an existing file or symlink is never overwritten or
 * followed. If writing fails after the file was created, the partial file is removed.
 */
async function writeExclusive(filePath: string, content: string | Buffer): Promise<void> {
  let handle;
  try {
    handle = await open(filePath, "wx", 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new ReportWriteError("file_exists", `Refusing to overwrite existing file: ${filePath}`);
    }
    throw new ReportWriteError("write_failed", `Could not create ${filePath}`);
  }
  let isWritten = false;
  try {
    await handle.writeFile(content);
    isWritten = true;
  } catch {
    throw new ReportWriteError("write_failed", `Could not write ${filePath}`);
  } finally {
    await handle.close().catch(() => undefined);
    if (!isWritten) await unlink(filePath).catch(() => undefined);
  }
}

async function pathExists(filePath: string): Promise<boolean> {
  try {
    await lstat(filePath);
    return true;
  } catch {
    return false;
  }
}

/** Renders one report format. Used by the file export and by the dashboard's browser download. */
export async function renderReport(
  result: ScanResult,
  format: "html" | "pdf",
): Promise<string | Buffer> {
  try {
    return format === "html" ? renderHtmlReport(result) : await renderPdfReport(result);
  } catch {
    throw new ReportWriteError(
      "render_failed",
      `Could not render the ${format.toUpperCase()} report.`,
    );
  }
}

/**
 * Renders and writes the requested report formats into the user-given directory. Both formats
 * come from the same ScanResult. All-or-nothing: everything is rendered and every target name is
 * checked before the first write, and files created by this call are removed if a later one
 * fails. Files are created with mode 0600 and never overwritten.
 */
export async function writeReports(
  result: ScanResult,
  options: WriteReportsOptions,
): Promise<WrittenReport[]> {
  const directory = await resolveOutputDir(options.outputDir);
  const baseName = buildReportBaseName(result);
  const formats: Array<"html" | "pdf"> =
    options.format === "both" ? ["html", "pdf"] : [options.format];

  const planned: Array<{ format: "html" | "pdf"; filePath: string; content: string | Buffer }> = [];
  for (const format of formats) {
    planned.push({
      format,
      filePath: path.join(directory, `${baseName}.${format}`),
      content: await renderReport(result, format),
    });
  }
  for (const entry of planned) {
    if (await pathExists(entry.filePath)) {
      throw new ReportWriteError(
        "file_exists",
        `Refusing to overwrite existing file: ${entry.filePath}`,
      );
    }
  }

  const written: WrittenReport[] = [];
  try {
    for (const entry of planned) {
      await writeExclusive(entry.filePath, entry.content);
      written.push({ format: entry.format, filePath: entry.filePath });
    }
  } catch (error) {
    await Promise.all(written.map((entry) => unlink(entry.filePath).catch(() => undefined)));
    throw error;
  }
  return written;
}

/**
 * True when `candidate` is `directory` itself or inside it, after resolving symlinks of the parts
 * that exist. Used to warn before saving a report inside the Git repository.
 */
export async function isPathInsideDirectory(
  candidate: string,
  directory: string,
): Promise<boolean> {
  const resolveExisting = async (target: string): Promise<string> => {
    const absolute = path.resolve(target);
    try {
      return await realpath(absolute);
    } catch {
      const parent = path.dirname(absolute);
      if (parent === absolute) return absolute;
      return path.join(await resolveExisting(parent), path.basename(absolute));
    }
  };
  const child = await resolveExisting(candidate);
  const parent = await resolveExisting(directory);
  const relative = path.relative(parent, child);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}
