import { constants, type BigIntStats, type Dir } from "node:fs";
import { lstat, open, opendir, stat as statFollowing } from "node:fs/promises";

/** What made a file unsafe to read, so a block reason can say what was actually found. */
export type UnsafeKind = "symlink" | "special" | "too-large" | "unreadable";

/**
 * Result of reading a small metadata file from inside a scanned repository's `.git` directory.
 * `unsafe` covers everything that is not a plain, small, regular file: a symbolic link, a FIFO,
 * a device, a directory, an oversized file, a read error, or a file that changed while opening.
 */
export type SafeReadResult =
  { state: "absent" } | { state: "ok"; text: string } | { state: "unsafe"; found: UnsafeKind };

const unsafe = (found: UnsafeKind): { state: "unsafe"; found: UnsafeKind } => ({
  state: "unsafe",
  found,
});

/**
 * Reads at most `maxBytes` of a regular file without following symlinks and without ever
 * blocking. The file lives in a repository PGARD does not trust, so `/dev/zero`, a FIFO or a
 * multi-gigabyte file in its place must not exhaust memory or hang. Only a missing file
 * (`ENOENT`) is `absent`; every other problem is `unsafe`, so callers fail closed.
 */
export async function readSmallRegularFile(
  filePath: string,
  maxBytes: number,
): Promise<SafeReadResult> {
  const read = await readSmallRegularFileBytes(filePath, maxBytes);
  return read.state === "ok" ? { state: "ok", text: read.bytes.toString("utf8") } : read;
}

export type SafeBytesResult =
  { state: "absent" } | { state: "ok"; bytes: Buffer } | { state: "unsafe"; found: UnsafeKind };

/** `readSmallRegularFile`, returning the bytes (for callers that decode them themselves). */
export async function readSmallRegularFileBytes(
  filePath: string,
  maxBytes: number,
): Promise<SafeBytesResult> {
  const stats = await lstat(filePath, { bigint: true }).catch(
    (error: NodeJS.ErrnoException) => error,
  );
  if (stats instanceof Error) {
    return (stats as NodeJS.ErrnoException).code === "ENOENT"
      ? { state: "absent" }
      : unsafe("unreadable");
  }
  if (stats.isSymbolicLink()) return unsafe("symlink");
  if (!stats.isFile()) return unsafe("special");
  if (stats.size > BigInt(maxBytes)) return unsafe("too-large");
  const noFollow = constants.O_NOFOLLOW;
  let handle;
  try {
    // O_NOFOLLOW: a file swapped for a symlink after lstat is not followed.
    // O_NONBLOCK: a file swapped for a FIFO cannot block the open.
    handle = await open(
      filePath,
      constants.O_RDONLY | (noFollow ?? 0) | (constants.O_NONBLOCK ?? 0),
    );
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile()) return unsafe("special");
    if (opened.size > BigInt(maxBytes)) return unsafe("too-large");
    // Where O_NOFOLLOW does not exist (Windows), the handle must be the inspected file.
    if (noFollow === undefined && (opened.dev !== stats.dev || opened.ino !== stats.ino)) {
      return unsafe("unreadable");
    }
    const buffer = Buffer.alloc(maxBytes + 1);
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);
    if (bytesRead > maxBytes) return unsafe("too-large");
    return { state: "ok", bytes: buffer.subarray(0, bytesRead) };
  } catch {
    return unsafe("unreadable");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/** Why a directory was not opened. */
export type UnsafeDirectoryKind = "symlink" | "special" | "mount" | "changed" | "unreadable";

export type SafeDirectoryResult =
  | { state: "ok"; dir: Dir; dev: bigint }
  | { state: "absent" }
  | { state: "unsafe"; found: UnsafeDirectoryKind };

export interface OpenDirectoryOptions {
  /**
   * The walk's root may itself be reached through a link (the user chose it); every folder
   * below it never may.
   */
  allowSymlink?: boolean;
  /** The device of the walk's root: a folder on another device is a mount point, not entered. */
  expectedDev?: bigint;
  bufferSize?: number;
}

const sameObject = (a: { dev: bigint; ino: bigint }, b: { dev: bigint; ino: bigint }): boolean =>
  a.dev === b.dev && (a.ino === 0n || a.ino === b.ino); // Windows may report no inode

/**
 * Opens a folder of a tree PGARD does not trust for reading, without following a symbolic link
 * that was swapped in after the parent was listed (#427). `lstat` first: a link or a non-folder is
 * refused; then, where the system has `O_DIRECTORY` and `O_NOFOLLOW`, a handle opened with both
 * must be the very object `lstat` saw (`dev` and `ino`); then `opendir`, and `lstat` once more:
 * a folder replaced between the checks and the open is refused, never read. A folder on another
 * device than `expectedDev` is a mount point (a network share, a FUSE mount, another disk) and
 * is not entered.
 */
export async function openDirectoryNoFollow(
  directory: string,
  options: OpenDirectoryOptions = {},
): Promise<SafeDirectoryResult> {
  const inspect = (): Promise<BigIntStats> =>
    options.allowSymlink === true
      ? statFollowing(directory, { bigint: true })
      : lstat(directory, { bigint: true });
  const before = await inspect().catch((error: NodeJS.ErrnoException) => error);
  if (before instanceof Error) {
    return (before as NodeJS.ErrnoException).code === "ENOENT"
      ? { state: "absent" }
      : { state: "unsafe", found: "unreadable" };
  }
  if (before.isSymbolicLink()) return { state: "unsafe", found: "symlink" };
  if (!before.isDirectory()) return { state: "unsafe", found: "special" };
  if (options.expectedDev !== undefined && before.dev !== options.expectedDev) {
    return { state: "unsafe", found: "mount" };
  }
  if (
    options.allowSymlink !== true &&
    constants.O_DIRECTORY !== undefined &&
    constants.O_NOFOLLOW !== undefined
  ) {
    let handle;
    try {
      handle = await open(
        directory,
        constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW,
      );
      if (!sameObject(before, await handle.stat({ bigint: true }))) {
        return { state: "unsafe", found: "changed" };
      }
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      return { state: "unsafe", found: code === "ELOOP" ? "symlink" : "unreadable" };
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }
  let dir: Dir;
  try {
    dir = await opendir(directory, { bufferSize: options.bufferSize ?? 64 });
  } catch {
    return { state: "unsafe", found: "unreadable" };
  }
  const after = await inspect().catch(() => null);
  if (after === null || after.isSymbolicLink() || !sameObject(before, after)) {
    await dir.close().catch(() => undefined);
    return { state: "unsafe", found: "changed" };
  }
  return { state: "ok", dir, dev: before.dev };
}

/**
 * `.git`, also in another case on macOS and Windows, whose file systems ignore case: `.GIT` is
 * the same folder there and must not be walked as project files (#427).
 */
export function isGitDirectoryName(
  name: string,
  platform: NodeJS.Platform = process.platform,
): boolean {
  return platform === "darwin" || platform === "win32"
    ? name.toLowerCase() === ".git"
    : name === ".git";
}
