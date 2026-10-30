import { constants, rmSync } from "node:fs";
import { chmod, lstat, mkdir, mkdtemp, open, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

/**
 * The redirect file the browser is opened with (#419 review; the approach of Jupyter's
 * `use_redirect_file`). The one-time link must never be on an opener's command line: on macOS
 * `ps -axww` shows every user's arguments, on Linux `/proc/<pid>/cmdline` is world-readable (and
 * `xdg-open` is a shell script whose children carry the argument too), so another local user
 * could read the token and exchange it first (Origin only stops browsers). Instead the link is
 * written into a 0600 file inside a fresh 0700 directory, and only that file's path is passed
 * to the opener. The file redirects the browser to the link and is deleted after the exchange,
 * when the unused link expires and when the server stops.
 */

/** The file's name inside its directory; the opener accepts no other. */
export const REDIRECT_FILE_NAME = "open-pgard.html";
/** The prefix of the directory under the OS temp folder. */
export const REDIRECT_DIR_PREFIX = "pgard-open-";

/** The only URL a redirect file may point to: PGARD's own local link with its token. */
export const REDIRECT_TARGET = /^http:\/\/127\.0\.0\.1:\d+\/#token=[A-Za-z0-9_-]+$/;

export interface RedirectFile {
  /** The redirect root the folder was made in (`redirectRoot`). */
  root: string;
  dir: string;
  file: string;
  /** Deletes the file and its directory; idempotent, never throws. */
  remove(): Promise<void>;
  /** The same, synchronously (for `process.on("exit")`). */
  removeSync(): void;
}

export class RedirectFileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RedirectFileError";
  }
}

const escapeHtml = (value: string): string =>
  value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

/** A JS string literal that is also safe inside a `<script>` element. */
const scriptString = (value: string): string =>
  JSON.stringify(value).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026");

/** The page: a meta refresh, a `location.replace` and a visible link, all to `url`. */
export function redirectPage(url: string): string {
  if (!REDIRECT_TARGET.test(url)) throw new RedirectFileError("Not PGARD's local link.");
  const attribute = escapeHtml(url);
  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="referrer" content="no-referrer">',
    `<meta http-equiv="refresh" content="0;url=${attribute}">`,
    "<title>Opening PGARD</title>",
    `<script>location.replace(${scriptString(url)});</script>`,
    "</head>",
    "<body>",
    `<p><a href="${attribute}">Open PGARD</a></p>`,
    "</body>",
    "</html>",
    "",
  ].join("\n");
}

/**
 * Writes the redirect file: `mkdtemp` (a new directory only this user can enter, 0700), then
 * the file created exclusively (`O_EXCL`, never following a link, 0600). An existing file or a
 * link in its place is refused, never overwritten.
 */
export async function createRedirectFile(
  url: string,
  options: { tmpRoot?: string; fileName?: string } = {},
): Promise<RedirectFile> {
  const content = redirectPage(url);
  const root = options.tmpRoot ?? (await redirectRoot());
  const dir = await mkdtemp(path.join(root, REDIRECT_DIR_PREFIX));
  let isRemoved = false;
  const removeSync = (): void => {
    if (isRemoved) return;
    isRemoved = true;
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // A temp file left behind is harmless once the server stops (the link is dead then).
    }
  };
  const remove = async (): Promise<void> => {
    if (isRemoved) return;
    isRemoved = true;
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  };
  const file = path.join(dir, options.fileName ?? REDIRECT_FILE_NAME);
  try {
    await chmod(dir, 0o700);
    const flags =
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0);
    const handle = await open(file, flags, 0o600);
    try {
      await handle.writeFile(content, "utf8");
    } finally {
      await handle.close();
    }
  } catch (error) {
    await remove();
    throw error instanceof RedirectFileError
      ? error
      : new RedirectFileError("The redirect file could not be written.");
  }
  return { root, dir, file, remove, removeSync };
}

export interface RedirectRootContext {
  platform: NodeJS.Platform;
  env: Readonly<Record<string, string | undefined>>;
  homeDir: string;
  uid: number | undefined;
}

/** A directory we own, that only we can enter, and that is not a symbolic link. */
async function isPrivateDirectory(dir: string, uid: number | undefined): Promise<boolean> {
  try {
    const stats = await lstat(dir);
    return (
      stats.isDirectory() &&
      !stats.isSymbolicLink() &&
      (uid === undefined || stats.uid === uid) &&
      (stats.mode & 0o077) === 0
    );
  } catch {
    return false;
  }
}

/**
 * Where the redirect folders go. macOS and Windows: the OS temp folder (per user on both).
 * Linux and the like: `$XDG_RUNTIME_DIR` when it is a private directory of ours (Snap browsers
 * on Ubuntu cannot read `/tmp`), else `~/.cache/pgard/open` (created 0700, checked to be ours
 * and private).
 */
export async function redirectRoot(
  context: RedirectRootContext = {
    platform: process.platform,
    env: process.env,
    homeDir: os.homedir(),
    uid: process.getuid?.(),
  },
): Promise<string> {
  const { platform, env, homeDir, uid } = context;
  if (platform === "darwin" || platform === "win32") return os.tmpdir();
  const runtime = env.XDG_RUNTIME_DIR ?? "";
  if (path.isAbsolute(runtime) && (await isPrivateDirectory(runtime, uid))) return runtime;
  if (!path.isAbsolute(homeDir))
    throw new RedirectFileError("No home folder for the redirect file.");
  const cache = path.join(homeDir, ".cache", "pgard", "open");
  await mkdir(cache, { recursive: true, mode: 0o700 }).catch(() => undefined);
  if (!(await isPrivateDirectory(cache, uid))) {
    throw new RedirectFileError("The redirect folder is not private.");
  }
  return cache;
}

/** `pgard-open-` plus the six characters `mkdtemp` adds. */
const REDIRECT_DIR_NAME = /^pgard-open-[A-Za-z0-9]{6}$/;

/**
 * The opener's argument must be exactly our redirect file: absolute and normalized, named
 * `REDIRECT_FILE_NAME`, directly inside a `pgard-open-XXXXXX` folder that sits directly in
 * `root` (our redirect root). The parent path may hold letters and digits of any script and
 * spaces (a Korean user name on Windows), never a character a shell, cmd or rundll32 would
 * treat specially. The path is always one argv element (no shell).
 */
export function isOurRedirectFile(
  filePath: string,
  redirectDir: string,
  platform: NodeJS.Platform,
  root: string,
): boolean {
  const paths = platform === "win32" ? path.win32 : path.posix;
  if (!paths.isAbsolute(filePath) || paths.normalize(filePath) !== filePath) return false;
  if (!/^[\p{L}\p{N}\p{M} _.~:/\\()-]+$/u.test(filePath)) return false;
  return (
    paths.dirname(filePath) === redirectDir &&
    paths.basename(filePath) === REDIRECT_FILE_NAME &&
    REDIRECT_DIR_NAME.test(paths.basename(redirectDir)) &&
    paths.isAbsolute(root) &&
    paths.dirname(redirectDir) === paths.resolve(root)
  );
}
