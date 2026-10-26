import os from "node:os";
import path from "node:path";

export interface StorePathInput {
  platform?: NodeJS.Platform;
  env?: Readonly<Record<string, string | undefined>>;
  homeDir?: string;
}

const DIRECTORY_NAME = "pgard";

/**
 * Directory of the local result store, in the per-user app-data location of the OS, never in a
 * project:
 * - macOS: `~/Library/Application Support/pgard`
 * - Linux and others: `$XDG_DATA_HOME/pgard` (only if absolute, as the XDG spec requires), else
 *   `~/.local/share/pgard`
 * - Windows: `%LOCALAPPDATA%\pgard` (only if absolute), else `~\AppData\Local\pgard`
 *
 * Returns `null` when no home directory can be determined; the store is then unavailable.
 * Pure: it creates nothing.
 */
export function resolveStoreDirectory(input: StorePathInput = {}): string | null {
  const platform = input.platform ?? process.platform;
  const env = input.env ?? process.env;
  const flavor = platform === "win32" ? path.win32 : path.posix;
  const homeDir = input.homeDir ?? os.homedir();
  const hasHome = homeDir !== "" && flavor.isAbsolute(homeDir);
  const absolute = (value: string | undefined): string | null =>
    value !== undefined && value !== "" && flavor.isAbsolute(value) ? value : null;

  if (platform === "win32") {
    const base =
      absolute(env.LOCALAPPDATA) ?? (hasHome ? flavor.join(homeDir, "AppData", "Local") : null);
    return base === null ? null : flavor.join(base, DIRECTORY_NAME);
  }
  if (platform === "darwin") {
    return hasHome ? flavor.join(homeDir, "Library", "Application Support", DIRECTORY_NAME) : null;
  }
  const base =
    absolute(env.XDG_DATA_HOME) ?? (hasHome ? flavor.join(homeDir, ".local", "share") : null);
  return base === null ? null : flavor.join(base, DIRECTORY_NAME);
}
