import { realpath } from "node:fs/promises";
import path from "node:path";
import { isValidPort } from "@pgard/http-local";
import { findGitRoot } from "@pgard/scan-core";

export interface LauncherOptions {
  projectRoot: string;
  presetTargetPort: number | null;
  /** `--no-browser`: never open GitHub pages automatically (links are still shown). */
  noBrowser: boolean;
}

export class LauncherUsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LauncherUsageError";
  }
}

/**
 * Parses `--project-root <abs> [--target-port N]` as passed by `pgard dashboard`. The project
 * root must be absolute and must be exactly a Git root; the browser can never change it.
 */
export async function parseLauncherArgs(
  argv: readonly string[],
  resolveGitRoot: (cwd: string) => Promise<string | null> = findGitRoot,
): Promise<LauncherOptions> {
  let projectRoot: string | null = null;
  let presetTargetPort: number | null = null;
  let noBrowser = false;
  for (let index = 0; index < argv.length; index += 2) {
    const name = argv[index];
    if (name === "--no-browser" && !noBrowser) {
      noBrowser = true;
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
  return { projectRoot: resolvedRoot, presetTargetPort, noBrowser };
}
