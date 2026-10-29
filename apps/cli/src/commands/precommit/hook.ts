import { constants } from "node:fs";
import { lstat, mkdir, open, rename, unlink, type FileHandle } from "node:fs/promises";
import path from "node:path";

/**
 * The hook file PGARD writes and the only file `uninstall` removes. The second line is the
 * marker: a hook is "written by PGARD" only when it starts with exactly these two lines and is
 * small. The script fails closed: without `pgard` on PATH it blocks the commit and says why,
 * instead of letting unscanned changes through.
 */
export const HOOK_MARKER = "# pgard-precommit-hook v1";
export const HOOK_FILE_NAME = "pre-commit";
const HEAD_LINES = `#!/bin/sh\n${HOOK_MARKER}\n`;
const MAX_HOOK_BYTES = 4096;
const MAX_BACKUP_NUMBER = 50;

export const HOOK_SCRIPT = `${HEAD_LINES}# Written by \`pgard precommit install\`; remove it with \`pgard precommit uninstall\`.
# Skip it once with \`git commit --no-verify\`. Mode (block or warn) is set in pgard.config.json.
if ! command -v pgard >/dev/null 2>&1; then
  echo "pgard: command not found. The staged changes were NOT scanned." >&2
  echo "Install pgard, or remove this hook with: pgard precommit uninstall" >&2
  exit 1
fi
exec pgard precommit
`;

/**
 * Every script PGARD has written (only one so far). A hook counts as PGARD's only when it is
 * exactly one of these: a file that merely carries the marker, or was edited afterwards, may hold
 * somebody else's commands and is treated like any other hook.
 */
const KNOWN_HOOK_SCRIPTS: readonly string[] = [HOOK_SCRIPT];

/** True when `content` is a script PGARD wrote (line endings aside). */
export function isPgardHook(content: string): boolean {
  return (
    content.length <= MAX_HOOK_BYTES && KNOWN_HOOK_SCRIPTS.includes(content.replace(/\r\n/g, "\n"))
  );
}

export type InstallOutcome =
  | { kind: "installed"; file: string }
  | { kind: "already"; file: string }
  | { kind: "needs_terminal"; file: string }
  | { kind: "declined"; file: string }
  | { kind: "replaced"; file: string; backup: string }
  | { kind: "failed" };

export type UninstallOutcome =
  | { kind: "removed"; file: string; backup: string | null }
  | { kind: "absent"; backup: string | null }
  | { kind: "not_ours"; file: string }
  | { kind: "failed" };

/** Reads a hook for comparison: a regular file of at most MAX_HOOK_BYTES, never through a link. */
async function readOwnHook(file: string): Promise<string | null> {
  let handle: FileHandle | undefined;
  try {
    handle = await open(
      file,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
    );
    const stats = await handle.stat();
    if (!stats.isFile() || stats.size > MAX_HOOK_BYTES) return null;
    const buffer = Buffer.alloc(MAX_HOOK_BYTES + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > MAX_HOOK_BYTES) return null;
    return buffer.subarray(0, bytesRead).toString("utf8");
  } catch {
    return null;
  } finally {
    await handle?.close();
  }
}

async function exists(file: string): Promise<boolean> {
  return (await lstat(file).catch(() => null)) !== null;
}

/** `pre-commit.pgard-backup`, then `.1`, `.2`...: the first name nothing uses. */
async function freeBackupName(hooksDir: string): Promise<string | null> {
  for (let number = 0; number <= MAX_BACKUP_NUMBER; number += 1) {
    const name = `${HOOK_FILE_NAME}.pgard-backup${number === 0 ? "" : `.${number}`}`;
    if (!(await exists(path.join(hooksDir, name)))) return name;
  }
  return null;
}

/** Creates `file` exclusively (`wx`) with mode 0755; fails if anything is there. */
async function createExclusive(file: string, content: string): Promise<void> {
  const handle = await open(file, "wx", 0o755);
  try {
    await handle.writeFile(content, "utf8");
    // The creation mode is cut by the umask; the hook must be executable.
    await handle.chmod(0o755);
  } finally {
    await handle.close();
  }
}

export interface InstallOptions {
  /** Asks whether to replace a hook PGARD did not write; `null` when there is no terminal. */
  confirmReplace: ((backupName: string) => Promise<boolean>) | null;
}

/**
 * Writes the hook into `hooksDir`, which the caller has already checked (the repository's own
 * resolved hooks directory, not a link out of it). Nothing outside `hooksDir` is touched.
 *
 * - No hook there: created exclusively.
 * - A hook PGARD wrote (an exact copy of its script): kept as it is.
 * - Any other hook (including a link): only with the user's confirmation and a terminal; it is
 *   moved aside to a backup name first, never overwritten.
 */
export async function installHook(
  hooksDir: string,
  options: InstallOptions,
): Promise<InstallOutcome> {
  const target = path.join(hooksDir, HOOK_FILE_NAME);
  try {
    if (!(await exists(hooksDir))) await mkdir(hooksDir, { mode: 0o755 });
    const stats = await lstat(target).catch((error: NodeJS.ErrnoException) =>
      error.code === "ENOENT" ? null : Promise.reject(error),
    );
    if (stats === null) {
      await createExclusive(target, HOOK_SCRIPT);
      return { kind: "installed", file: target };
    }
    const current = stats.isFile() ? await readOwnHook(target) : null;
    if (current !== null && isPgardHook(current)) return { kind: "already", file: target };
    // Somebody else's hook.
    if (options.confirmReplace === null) return { kind: "needs_terminal", file: target };
    const backupName = await freeBackupName(hooksDir);
    if (backupName === null) return { kind: "failed" };
    if (!(await options.confirmReplace(backupName))) return { kind: "declined", file: target };
    const backup = path.join(hooksDir, backupName);
    await rename(target, backup);
    try {
      await createExclusive(target, HOOK_SCRIPT);
    } catch (error) {
      // Put the original back so a failure leaves the repository as it was.
      await rename(backup, target).catch(() => undefined);
      throw error;
    }
    return { kind: "replaced", file: target, backup };
  } catch {
    return { kind: "failed" };
  }
}

/** The newest backup an earlier install left, for a hint after uninstall. */
async function findBackup(hooksDir: string): Promise<string | null> {
  for (let number = MAX_BACKUP_NUMBER; number >= 0; number -= 1) {
    const name = `${HOOK_FILE_NAME}.pgard-backup${number === 0 ? "" : `.${number}`}`;
    if (await exists(path.join(hooksDir, name))) return path.join(hooksDir, name);
  }
  return null;
}

/** Removes the hook only when PGARD wrote it (a link, a changed file or another tool's hook stays). */
export async function uninstallHook(hooksDir: string): Promise<UninstallOutcome> {
  const target = path.join(hooksDir, HOOK_FILE_NAME);
  try {
    const stats = await lstat(target).catch((error: NodeJS.ErrnoException) =>
      error.code === "ENOENT" || error.code === "ENOTDIR" ? null : Promise.reject(error),
    );
    const backup = await findBackup(hooksDir);
    if (stats === null) return { kind: "absent", backup };
    const current = stats.isFile() ? await readOwnHook(target) : null;
    if (current === null || !isPgardHook(current)) return { kind: "not_ours", file: target };
    await unlink(target);
    return { kind: "removed", file: target, backup };
  } catch {
    return { kind: "failed" };
  }
}
