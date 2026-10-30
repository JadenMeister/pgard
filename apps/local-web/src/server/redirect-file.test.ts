import {
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { bindRedirectCleanup } from "./launch-output.js";
import {
  createRedirectFile,
  REDIRECT_DIR_PREFIX,
  REDIRECT_FILE_NAME,
  redirectPage,
  RedirectFileError,
} from "./redirect-file.js";
import { URL_TOKEN_TTL_MS } from "./session/url-session.js";

/** #419 review: the link goes into a private file; only the file's path reaches the opener. */
const URL = "http://127.0.0.1:43123/#token=abcDEF012_-tokenValue";

const roots: string[] = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});
function tmpRoot(): string {
  const root = mkdtempSync(path.join(os.tmpdir(), "pgard-redirect-test-"));
  roots.push(root);
  return root;
}

describe("redirectPage", () => {
  it("redirects by meta refresh and location.replace, with a visible link", () => {
    const html = redirectPage(URL);
    expect(html).toContain(`<meta http-equiv="refresh" content="0;url=${URL}">`);
    expect(html).toContain(`location.replace("${URL}")`);
    expect(html).toContain(`<a href="${URL}">Open PGARD</a>`);
    expect(html).toContain('<meta name="referrer" content="no-referrer">');
  });

  it("accepts only PGARD's own tokened link, so nothing can break out of the markup", () => {
    for (const bad of [
      'http://127.0.0.1:1/#token=a"><script>alert(1)</script>',
      "http://127.0.0.1:1/#token=a</script><script>x()</script>",
      "http://127.0.0.1:1/#token=a'b",
      "http://127.0.0.1:1/",
      "javascript:alert(1)",
      "http://evil.example/#token=abc",
    ]) {
      expect(() => redirectPage(bad)).toThrow(RedirectFileError);
    }
  });
});

describe.skipIf(process.platform === "win32")("createRedirectFile", () => {
  it("writes a 0600 file inside a new 0700 directory under the temp root", async () => {
    const root = tmpRoot();
    const redirect = await createRedirectFile(URL, { tmpRoot: root });
    expect(path.dirname(redirect.dir)).toBe(root);
    expect(path.basename(redirect.dir).startsWith(REDIRECT_DIR_PREFIX)).toBe(true);
    expect(redirect.file).toBe(path.join(redirect.dir, REDIRECT_FILE_NAME));
    expect(statSync(redirect.dir).mode & 0o777).toBe(0o700);
    expect(statSync(redirect.file).mode & 0o777).toBe(0o600);
    expect(readFileSync(redirect.file, "utf8")).toBe(redirectPage(URL));
    await redirect.remove();
    expect(existsSync(redirect.dir)).toBe(false);
    await redirect.remove();
    redirect.removeSync();
  });

  it("refuses an existing file or a link in its place (O_EXCL, no follow) and leaves nothing", async () => {
    const root = tmpRoot();
    const target = path.join(root, "victim.txt");
    // A file that already exists at the path is never overwritten (O_EXCL).
    const existing = path.join(root, "existing.html");
    writeFileSync(existing, "keep me");
    await expect(
      createRedirectFile(URL, { tmpRoot: root, fileName: "../existing.html" }),
    ).rejects.toBeInstanceOf(RedirectFileError);
    expect(readFileSync(existing, "utf8")).toBe("keep me");
    // A symbolic link in its place is not followed (O_EXCL with O_CREAT never follows it).
    symlinkSync(target, path.join(root, "planted.html"));
    await expect(
      createRedirectFile(URL, { tmpRoot: root, fileName: "../planted.html" }),
    ).rejects.toBeInstanceOf(RedirectFileError);
    expect(existsSync(target)).toBe(false);
    // Only the planted link is left; every pgard-open- directory was removed again.
    expect(
      (await import("node:fs")).readdirSync(root).filter((n) => n.startsWith(REDIRECT_DIR_PREFIX)),
    ).toEqual([]);
  });
});

describe.skipIf(process.platform === "win32")("bindRedirectCleanup", () => {
  async function fresh() {
    return createRedirectFile(URL, { tmpRoot: tmpRoot() });
  }

  it("deletes the file right after the exchange", async () => {
    const redirect = await fresh();
    const cleanup = bindRedirectCleanup(redirect);
    cleanup.onConnected();
    await vi.waitFor(() => expect(existsSync(redirect.dir)).toBe(false));
  });

  it("deletes the file when the server stops, and on process exit", async () => {
    const first = await fresh();
    await bindRedirectCleanup(first).onStop();
    expect(existsSync(first.dir)).toBe(false);
    const second = await fresh();
    bindRedirectCleanup(second).onExit();
    expect(existsSync(second.dir)).toBe(false);
  });

  it("deletes the file when the unused link expires after 10 minutes", async () => {
    const redirect = await fresh();
    let run: (() => void) | null = null;
    let delay = 0;
    bindRedirectCleanup(redirect, {
      setTimer: (callback, ms) => {
        run = callback;
        delay = ms;
        return {};
      },
      clearTimer: () => undefined,
    });
    expect(delay).toBe(URL_TOKEN_TTL_MS);
    expect(existsSync(redirect.file)).toBe(true);
    (run as unknown as () => void)();
    await vi.waitFor(() => expect(existsSync(redirect.dir)).toBe(false));
  });

  it("does nothing without a file", async () => {
    const cleanup = bindRedirectCleanup(null);
    cleanup.onConnected();
    cleanup.onExit();
    await cleanup.onStop();
  });
});
