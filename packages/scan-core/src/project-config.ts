import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import path from "node:path";
import {
  MAX_PROJECT_CONFIG_BYTES,
  PROJECT_CONFIG_FILE,
  compileGlob,
  formatSeverityBreakdown,
  matchesEverything,
  parseProjectConfig,
  type Coverage,
  type ProjectConfig,
  type SuppressionSummary,
} from "@pgard/findings";

/**
 * Outcome of looking for `pgard.config.json` at the Git root.
 *
 * Fail-safe: an unreadable or invalid file is never fatal and never partly applied. The scan runs
 * as if there were no config (nothing is excluded, no extra test directories), so an invalid file
 * cannot hide a finding, and the problems are reported in coverage (`source:config`, partial).
 */
export type ProjectConfigLoad =
  | { state: "absent" }
  | { state: "loaded"; config: ProjectConfig }
  | { state: "invalid"; problems: string[] };

/** Test hooks: run code between the inspection and the open, or act as a system without O_NOFOLLOW. */
export interface LoadProjectConfigHooks {
  afterInspect?: () => Promise<void> | void;
  pretendNoNoFollow?: boolean;
}

/**
 * Reads the project configuration read-only: the file must be a regular file (a symbolic link is
 * refused, also at open time through `O_NOFOLLOW`, or on Windows by comparing the opened file's
 * device and inode with the inspected one), at most 64 KiB, valid UTF-8 and valid
 * according to `parseProjectConfig`. The content is parsed as data and never executed.
 */
export async function loadProjectConfig(
  projectRoot: string,
  hooks: LoadProjectConfigHooks = {},
): Promise<ProjectConfigLoad> {
  const file = path.join(projectRoot, PROJECT_CONFIG_FILE);
  const noFollow = hooks.pretendNoNoFollow === true ? undefined : constants.O_NOFOLLOW;
  const stats = await lstat(file, { bigint: true }).catch((error: NodeJS.ErrnoException) => error);
  if (stats instanceof Error) {
    return stats.code === "ENOENT" || stats.code === "ENOTDIR"
      ? { state: "absent" }
      : { state: "invalid", problems: [`${PROJECT_CONFIG_FILE} could not be inspected`] };
  }
  if (stats.isSymbolicLink()) {
    return {
      state: "invalid",
      problems: [`${PROJECT_CONFIG_FILE} is a symbolic link; it is refused and not followed`],
    };
  }
  if (!stats.isFile()) {
    return { state: "invalid", problems: [`${PROJECT_CONFIG_FILE} is not a regular file`] };
  }
  if (stats.size > BigInt(MAX_PROJECT_CONFIG_BYTES)) {
    return {
      state: "invalid",
      problems: [`${PROJECT_CONFIG_FILE} is larger than ${MAX_PROJECT_CONFIG_BYTES} bytes`],
    };
  }
  await hooks.afterInspect?.();
  let text: string;
  let handle;
  try {
    // O_NOFOLLOW: a file swapped for a symlink after the check above is not followed.
    // O_NONBLOCK: a file swapped for a FIFO cannot block the scan.
    handle = await open(file, constants.O_RDONLY | (noFollow ?? 0) | (constants.O_NONBLOCK ?? 0));
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile()) {
      return { state: "invalid", problems: [`${PROJECT_CONFIG_FILE} is not a regular file`] };
    }
    // Where O_NOFOLLOW does not exist (Windows), the handle must be the very file that was
    // inspected: a swap for a link to another file shows as a different device or inode.
    if (noFollow === undefined && (opened.dev !== stats.dev || opened.ino !== stats.ino)) {
      return {
        state: "invalid",
        problems: [`${PROJECT_CONFIG_FILE} changed while it was being opened; it is refused`],
      };
    }
    const buffer = Buffer.alloc(MAX_PROJECT_CONFIG_BYTES + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > MAX_PROJECT_CONFIG_BYTES) {
      return {
        state: "invalid",
        problems: [
          `${PROJECT_CONFIG_FILE} grew larger than ${MAX_PROJECT_CONFIG_BYTES} bytes while it was being read`,
        ],
      };
    }
    text = new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, bytesRead));
  } catch (error) {
    const reason =
      error instanceof TypeError ? "is not valid UTF-8 text" : "could not be read or is a symlink";
    return { state: "invalid", problems: [`${PROJECT_CONFIG_FILE} ${reason}`] };
  } finally {
    await handle?.close();
  }
  const parsed = parseProjectConfig(text);
  return parsed.ok
    ? { state: "loaded", config: parsed.config }
    : { state: "invalid", problems: parsed.problems };
}

const MAX_PROBLEM_NOTE = 220;

function describeSuppressions(parsed: number, summary: SuppressionSummary | null): string {
  const noun = `${parsed} suppression${parsed === 1 ? "" : "s"}`;
  if (summary === null) return noun;
  const breakdown = formatSeverityBreakdown(summary.bySeverity);
  const severe = summary.bySeverity.critical + summary.bySeverity.high;
  const expired = summary.entries.filter((entry) => entry.state === "expired").length;
  const details = [
    `${summary.suppressed} finding${summary.suppressed === 1 ? "" : "s"} suppressed${breakdown === "" ? "" : ` (${breakdown})`}`,
    ...(severe > 0
      ? [`WARNING: ${severe} suppressed finding${severe === 1 ? " is" : "s are"} high or critical`]
      : []),
    ...(expired > 0 ? [`${expired} expired, not applied`] : []),
    ...(summary.incomplete ? ["matching stopped early"] : []),
  ];
  return `${noun} (${details.join(", ")})`;
}

/**
 * Coverage entry `source:config` for the configuration file, or null when there is none.
 * - invalid: `partial`, the scan ran with no config (nothing excluded), first problems quoted;
 * - loaded: `completed`, what was read; suppressions are applied and counted in the note (a suppressed
 *   finding is kept and listed apart); `testFindings` counts findings the config's `testDirectories` moved into the test
 *   group, which is shown so a config cannot demote findings without a trace;
 * - loaded with a `testDirectories` pattern that matches every file: `partial` with a WARNING.
 */
export function describeProjectConfig(
  load: ProjectConfigLoad,
  testFindings: number,
  budgetWarning: string | null = null,
  suppression: SuppressionSummary | null = null,
): Coverage | null {
  if (load.state === "absent") return null;
  if (load.state === "invalid") {
    const joined = load.problems.join("; ");
    const clipped =
      joined.length > MAX_PROBLEM_NOTE ? `${joined.slice(0, MAX_PROBLEM_NOTE - 3)}...` : joined;
    return {
      area: "source:config",
      scope: "code",
      status: "partial",
      ruleIds: [],
      note: `${PROJECT_CONFIG_FILE} is invalid and was ignored; the scan ran with no exclusions: ${clipped}.`,
    };
  }
  const { config } = load;
  const catchAll = config.testDirectories.filter((pattern) =>
    matchesEverything(compileGlob(pattern)),
  );
  const warning =
    catchAll.length > 0
      ? ` WARNING: testDirectories ${JSON.stringify(catchAll[0])} matches every file, so every finding is shown as test code.`
      : "";
  const count = (n: number, noun: string) => `${n} ${noun}${n === 1 ? "" : "s"}`;
  return {
    area: "source:config",
    scope: "code",
    status: warning === "" && budgetWarning === null ? "completed" : "partial",
    ruleIds: [],
    note: `${budgetWarning === null ? "" : `${budgetWarning} `}${PROJECT_CONFIG_FILE} read (version ${config.version}): ${count(config.exclude.length, "exclude pattern")}, ${count(config.testDirectories.length, "test directory pattern")} (${count(testFindings, "finding")} classified as test code by it), ${describeSuppressions(config.suppressions.length, suppression)}.${warning}`,
  };
}
