import { realpath } from "node:fs/promises";
import path from "node:path";
import { isValidPort } from "@pgard/http-local";
import { findGitRoot } from "@pgard/scan-core";

export interface LauncherOptions {
  /** The fixed project (`pgard dashboard`), or `null` in picker mode (`pgard web`). */
  projectRoot: string | null;
  presetTargetPort: number | null;
  /** `--no-browser`: never open GitHub pages automatically (links are still shown). */
  noBrowser: boolean;
  /** `--picker` (`pgard web`): the project is chosen in the browser, from the search scope. */
  picker: boolean;
  /** `--no-store` (picker only): neither the recent list nor the first-run roots are written. */
  noStore: boolean;
}

export class LauncherUsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LauncherUsageError";
  }
}

/**
 * Parses `--project-root <abs> [--target-port N]` as passed by `pgard dashboard`, or `--picker
 * [--no-store]` as passed by `pgard web`. A fixed project root must be absolute and exactly a Git
 * root; the browser can never change it. Picker mode takes no path at all: the search folders
 * live in the settings file, so no path ever shows up in the process list.
 */
export async function parseLauncherArgs(
  argv: readonly string[],
  resolveGitRoot: (cwd: string) => Promise<string | null> = findGitRoot,
): Promise<LauncherOptions> {
  let projectRoot: string | null = null;
  let presetTargetPort: number | null = null;
  let noBrowser = false;
  let picker = false;
  let noStore = false;
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    if (name === "--no-browser" && !noBrowser) {
      noBrowser = true;
      index -= 1;
      continue;
    }
    if (name === "--picker" && !picker) {
      picker = true;
      index -= 1;
      continue;
    }
    if (name === "--no-store" && !noStore) {
      noStore = true;
      index -= 1;
      continue;
    }
    const value = argv[index + 1];
    if (value === undefined) throw new LauncherUsageError(`Missing value for ${name ?? "option"}.`);
    if (name === "--project-root" && projectRoot === null) {
      projectRoot = value;
    } else if (name === "--target-port" && presetTargetPort === null) {
      const port = /^[0-9]{1,5}$/.test(value) ? Number(value) : Number.NaN;
      if (!isValidPort(port)) throw new LauncherUsageError("--target-port must be 1-65535.");
      presetTargetPort = port;
    } else {
      throw new LauncherUsageError("Usage: pgard dashboard (started by the pgard CLI).");
    }
  }
  if (picker) {
    if (projectRoot !== null || presetTargetPort !== null) {
      throw new LauncherUsageError("--picker takes no project root and no target port.");
    }
    return { projectRoot: null, presetTargetPort: null, noBrowser, picker: true, noStore };
  }
  if (noStore) throw new LauncherUsageError("--no-store is only available with --picker.");
  if (projectRoot === null || !path.isAbsolute(projectRoot)) {
    throw new LauncherUsageError("--project-root must be an absolute path.");
  }
  const gitRoot = await resolveGitRoot(projectRoot);
  const [resolvedRoot, resolvedGitRoot] = await Promise.all([
    realpath(projectRoot).catch(() => null),
    gitRoot === null ? null : realpath(gitRoot).catch(() => null),
  ]);
  if (resolvedRoot === null || resolvedGitRoot === null || resolvedRoot !== resolvedGitRoot) {
    throw new LauncherUsageError("--project-root must be the root of a Git repository.");
  }
  return { projectRoot: resolvedRoot, presetTargetPort, noBrowser, picker: false, noStore: false };
}
