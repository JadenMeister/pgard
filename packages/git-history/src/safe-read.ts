import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";

/** What made a file unsafe to read, so a block reason can say what was actually found. */
export type UnsafeKind = "symlink" | "special" | "too-large" | "unreadable";

/**
 * Result of reading a small metadata file from inside a scanned repository's `.git` directory.
 * `unsafe` covers everything that is not a plain, small, regular file: a symbolic link, a FIFO,
 * a device, a directory, an oversized file, a read error, or a file that changed while opening.
 */
export type SafeReadResult =
  { state: "absent" } | { state: "ok"; text: string } | { state: "unsafe"; found: UnsafeKind };

const unsafe = (found: UnsafeKind): SafeReadResult => ({ state: "unsafe", found });

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
    return { state: "ok", text: buffer.toString("utf8", 0, bytesRead) };
  } catch {
    return unsafe("unreadable");
  } finally {
    await handle?.close().catch(() => undefined);
  }
}
