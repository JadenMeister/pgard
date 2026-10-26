import os from "node:os";
import path from "node:path";

// TODO: unify with the result-store resolver (app-data directory in its own package) once both
// have landed. This is a minimal local resolver so advisory data does not depend on it.

export interface AppDataEnvironment {
  platform: NodeJS.Platform;
  env: Readonly<Record<string, string | undefined>>;
  homedir: string;
}

export function currentAppDataEnvironment(): AppDataEnvironment {
  let homedir = "";
  try {
    homedir = os.homedir();
  } catch {
    // no home directory (e.g. a service account without one)
  }
  return { platform: process.platform, env: process.env, homedir };
}

/**
 * PGARD's per-user data directory: `~/Library/Application Support/pgard` on macOS,
 * `$XDG_DATA_HOME/pgard` (default `~/.local/share/pgard`) on Linux and
 * `%LOCALAPPDATA%\pgard` on Windows. Returns `null` when no absolute base directory can be
 * determined (no usable home directory); callers must not guess a relative location.
 */
export function resolveAppDataDir(environment: AppDataEnvironment): string | null {
  const { platform, env, homedir } = environment;
  const flavour = platform === "win32" ? path.win32 : path.posix;
  const usableHome = homedir !== "" && flavour.isAbsolute(homedir) ? homedir : null;
  // XDG and Windows say a relative override must be ignored.
  const override = (value: string | undefined): string | null =>
    value !== undefined && value !== "" && flavour.isAbsolute(value) ? value : null;
  let base: string | null;
  if (platform === "darwin") {
    base =
      usableHome === null ? null : path.posix.join(usableHome, "Library", "Application Support");
  } else if (platform === "win32") {
    base =
      override(env["LOCALAPPDATA"]) ??
      (usableHome === null ? null : path.win32.join(usableHome, "AppData", "Local"));
  } else {
    base =
      override(env["XDG_DATA_HOME"]) ??
      (usableHome === null ? null : path.posix.join(usableHome, ".local", "share"));
  }
  return base === null ? null : flavour.join(base, "pgard");
}

/** Where verified OSV data lives: `<app data>/advisories/osv`. */
export function osvDataDir(appDataDir: string): string {
  return path.join(appDataDir, "advisories", "osv");
}
