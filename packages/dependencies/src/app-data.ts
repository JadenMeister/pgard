import os from "node:os";
import path from "node:path";

// TODO(#200): unify with the shared app-data helper once the result-store package lands on main.
// This is a minimal local resolver so advisory data has a home that does not depend on it.

export interface AppDataEnvironment {
  platform: NodeJS.Platform;
  env: Readonly<Record<string, string | undefined>>;
  homedir: string;
}

export function currentAppDataEnvironment(): AppDataEnvironment {
  return { platform: process.platform, env: process.env, homedir: os.homedir() };
}

function absoluteOr(value: string | undefined, fallback: string, join: typeof path.join): string {
  // XDG and Windows say a relative value must be ignored.
  return value !== undefined && value !== "" && path.isAbsolute(value) ? value : fallback;
}

/**
 * PGARD's per-user data directory: `~/Library/Application Support/pgard` on macOS,
 * `$XDG_DATA_HOME/pgard` (default `~/.local/share/pgard`) on Linux and
 * `%LOCALAPPDATA%\pgard` on Windows.
 */
export function resolveAppDataDir(environment: AppDataEnvironment): string {
  const { platform, env, homedir } = environment;
  if (platform === "darwin") {
    return path.posix.join(homedir, "Library", "Application Support", "pgard");
  }
  if (platform === "win32") {
    const base = absoluteOr(
      env["LOCALAPPDATA"],
      path.win32.join(homedir, "AppData", "Local"),
      path.win32.join,
    );
    return path.win32.join(base, "pgard");
  }
  const base = absoluteOr(
    env["XDG_DATA_HOME"],
    path.posix.join(homedir, ".local", "share"),
    path.posix.join,
  );
  return path.posix.join(base, "pgard");
}

/** Where verified OSV data lives: `<app data>/advisories/osv`. */
export function osvDataDir(appDataDir: string): string {
  return path.join(appDataDir, "advisories", "osv");
}
