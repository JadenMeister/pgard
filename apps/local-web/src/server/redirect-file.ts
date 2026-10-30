import { constants, rmSync } from "node:fs";
import { chmod, mkdtemp, open, rm } from "node:fs/promises";
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
  const dir = await mkdtemp(path.join(options.tmpRoot ?? os.tmpdir(), REDIRECT_DIR_PREFIX));
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
  return { dir, file, remove, removeSync };
}

/**
 * The opener's argument must be exactly our redirect file: an absolute path, named
 * `REDIRECT_FILE_NAME`, directly inside our own `pgard-open-` directory, with no character a
 * shell, cmd or rundll32 would treat specially.
 */
export function isOurRedirectFile(
  filePath: string,
  redirectDir: string,
  platform: NodeJS.Platform,
): boolean {
  const paths = platform === "win32" ? path.win32 : path.posix;
  if (!paths.isAbsolute(filePath) || paths.normalize(filePath) !== filePath) return false;
  if (!/^[A-Za-z0-9 _.~:/\\()-]+$/.test(filePath)) return false;
  return (
    paths.dirname(filePath) === redirectDir &&
    paths.basename(filePath) === REDIRECT_FILE_NAME &&
    paths.basename(redirectDir).startsWith(REDIRECT_DIR_PREFIX)
  );
}
