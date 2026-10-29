import { randomBytes } from "node:crypto";
import { constants as fsConstants, type Stats } from "node:fs";
import { lstat, mkdir, open, rename, unlink, type FileHandle } from "node:fs/promises";
import path from "node:path";

/**
 * Shared owner-only file helpers: a `0700` directory and `0600` files, no symbolic link ever
 * followed, size cap before parsing, temp file plus rename for writes. The result store and the
 * `pgard web` settings and recent-projects files both use them.
 */

export const SAFE_DIRECTORY_MODE = 0o700;
export const SAFE_FILE_MODE = 0o600;

export type SafeFileErrorCode =
  "too_large" | "symlink" | "not_directory" | "wrong_owner" | "permissions" | "would_overwrite";

export class SafeFileError extends Error {
  readonly code: SafeFileErrorCode;
  constructor(code: SafeFileErrorCode, message: string) {
    super(message);
    this.name = "SafeFileError";
    this.code = code;
  }
}

export interface SafeFileEnvironment {
  /** False on Windows, where mode and owner checks do not apply. */
  isPosix: boolean;
  /** `process.getuid` or a test stand-in. */
  getuid: () => number | undefined;
}

export const DEFAULT_SAFE_FILE_ENVIRONMENT: SafeFileEnvironment = {
  isPosix: process.platform !== "win32",
  getuid: () => process.getuid?.(),
};

const NO_FOLLOW = fsConstants.O_NOFOLLOW ?? 0;
const DIRECTORY_FLAG = fsConstants.O_DIRECTORY ?? 0;

export function errnoOf(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error
    ? String((error as { code: unknown }).code)
    : undefined;
}

/** Creates (owner-only) or validates a directory: no symlink, ours, 0700. */
export async function ensureOwnerOnlyDirectory(
  dir: string,
  environment: SafeFileEnvironment,
  create = true,
): Promise<void> {
  if (create) {
    try {
      await mkdir(dir, { mode: SAFE_DIRECTORY_MODE });
    } catch (error) {
      if (errnoOf(error) !== "EEXIST") throw error;
    }
  }
  const before = await lstat(dir);
  if (before.isSymbolicLink()) {
    throw new SafeFileError("symlink", "Refusing to use a symbolic link as a result directory.");
  }
  if (!before.isDirectory()) {
    throw new SafeFileError("not_directory", "A result directory path is not a directory.");
  }
  // Open without following a link planted since the lstat, then check the same inode.
  let handle: FileHandle;
  try {
    handle = await open(dir, fsConstants.O_RDONLY | DIRECTORY_FLAG | NO_FOLLOW);
  } catch (error) {
    if (errnoOf(error) === "ELOOP" || errnoOf(error) === "ENOTDIR") {
      throw new SafeFileError("symlink", "Refusing to use a symbolic link as a result directory.");
    }
    throw error;
  }
  try {
    const stat = await handle.stat();
    if (!stat.isDirectory() || stat.ino !== before.ino || stat.dev !== before.dev) {
      throw new SafeFileError("symlink", "A result directory changed while it was opened.");
    }
    if (environment.isPosix) {
      const uid = environment.getuid();
      if (uid !== undefined && stat.uid !== uid) {
        throw new SafeFileError("wrong_owner", "A result directory is owned by another user.");
      }
      if ((stat.mode & 0o777) !== SAFE_DIRECTORY_MODE) await handle.chmod(SAFE_DIRECTORY_MODE);
      const verified = await handle.stat();
      if ((verified.mode & 0o777) !== SAFE_DIRECTORY_MODE) {
        throw new SafeFileError("permissions", "Could not restrict a result directory to 0700.");
      }
    }
  } finally {
    await handle.close();
  }
}

/** Reads a regular file without following a symlink, capped before parsing. */
export async function readFileCapped(
  file: string,
  maxBytes: number,
  environment: SafeFileEnvironment,
  refuseWritableByOthers = false,
): Promise<string> {
  const before = await lstat(file);
  if (before.isSymbolicLink() || !before.isFile()) {
    throw new SafeFileError("symlink", "Not a regular file (symbolic links are never followed).");
  }
  const handle = await open(file, fsConstants.O_RDONLY | NO_FOLLOW);
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.ino !== before.ino || stat.dev !== before.dev) {
      throw new SafeFileError("symlink", "The file changed while it was opened.");
    }
    if (refuseWritableByOthers && environment.isPosix && (stat.mode & 0o022) !== 0) {
      throw new SafeFileError(
        "permissions",
        "The file can be written by other users, so it is not trusted. Delete it and set it again.",
      );
    }
    if (stat.size > maxBytes) {
      throw new SafeFileError("too_large", `The file is larger than ${maxBytes} bytes.`);
    }
    const buffer = Buffer.alloc(Math.min(stat.size, maxBytes));
    let offset = 0;
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
      if (bytesRead === 0) break;
      offset += bytesRead;
    }
    return buffer.subarray(0, offset).toString("utf8");
  } finally {
    await handle.close();
  }
}

/**
 * Writes `text` to a temp file in `dir` (owner-only, exclusive create, fsynced), lets
 * `checkExisting` refuse replacing whatever is at `finalName` (it is called only when the
 * existing entry is a regular file), then renames over the target.
 */
export async function writeFileAtomically(
  dir: string,
  finalName: string,
  text: string,
  environment: SafeFileEnvironment,
  options: { tempPrefix: string; checkExisting: (finalPath: string) => Promise<void> },
): Promise<void> {
  const finalPath = path.join(dir, finalName);
  const tempPath = path.join(
    dir,
    `${options.tempPrefix}${process.pid}-${randomBytes(8).toString("hex")}`,
  );
  // O_EXCL fails on any existing entry, including a planted symlink; O_NOFOLLOW adds a second guard.
  const handle = await open(
    tempPath,
    fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL | NO_FOLLOW,
    SAFE_FILE_MODE,
  );
  try {
    try {
      await handle.writeFile(text, "utf8");
      if (environment.isPosix) {
        await handle.chmod(SAFE_FILE_MODE);
        if (((await handle.stat()).mode & 0o777) !== SAFE_FILE_MODE) {
          throw new SafeFileError("permissions", "Could not restrict a result file to 0600.");
        }
      }
      await handle.sync();
    } finally {
      await handle.close();
    }
    let existing: Stats | null = null;
    try {
      existing = await lstat(finalPath);
    } catch (error) {
      if (errnoOf(error) !== "ENOENT") throw error;
    }
    if (existing !== null) {
      if (existing.isSymbolicLink() || !existing.isFile()) {
        throw new SafeFileError("symlink", "The target is not a regular file; not replacing it.");
      }
      await options.checkExisting(finalPath);
    }
    await rename(tempPath, finalPath);
  } catch (error) {
    await unlink(tempPath).catch(() => undefined);
    throw error;
  }
}
