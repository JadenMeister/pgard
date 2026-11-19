import { constants } from "node:fs";
import { lstat, open, type FileHandle } from "node:fs/promises";

/** Test hooks: run code between the inspection and the open, or act as a system without O_NOFOLLOW. */
export interface SafeOpenHooks {
  afterInspect?: () => Promise<void> | void;
  pretendNoNoFollow?: boolean;
}

/**
 * Opens a regular file of a tree PGARD does not trust, read-only, without following a link and
 * without blocking (#395). `lstat` first: a link or a non-file is refused. Then `O_NOFOLLOW`
 * and `O_NONBLOCK`; where the system has no `O_NOFOLLOW` (Windows), the opened handle must be
 * the very file `lstat` saw (`dev` and `ino`), so a link or junction swapped in after the
 * inspection is refused instead of followed. Returns `null` for anything unsafe or unreadable;
 * the caller fails closed. The caller closes the handle.
 */
export async function openRegularFileNoFollow(
  absolutePath: string,
  hooks: SafeOpenHooks = {},
): Promise<FileHandle | null> {
  const noFollow = hooks.pretendNoNoFollow === true ? undefined : constants.O_NOFOLLOW;
  let handle: FileHandle | undefined;
  try {
    const inspected = await lstat(absolutePath, { bigint: true });
    if (inspected.isSymbolicLink() || !inspected.isFile()) return null;
    await hooks.afterInspect?.();
    handle = await open(
      absolutePath,
      constants.O_RDONLY | (noFollow ?? 0) | (constants.O_NONBLOCK ?? 0),
    );
    const opened = await handle.stat({ bigint: true });
    if (!opened.isFile()) throw new Error("not a regular file");
    if (noFollow === undefined && (opened.dev !== inspected.dev || opened.ino !== inspected.ino)) {
      throw new Error("changed while opening");
    }
    return handle;
  } catch {
    await handle?.close().catch(() => undefined);
    return null;
  }
}
