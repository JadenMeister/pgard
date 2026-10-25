import { describe, expect, it, vi } from "vitest";
import { buildAppInstallUrl, isOpenableGitHubUrl } from "./app-install.js";
import { openerCommandFor, openGitHubUrl } from "./open-url.js";

describe("buildAppInstallUrl", () => {
  it("builds the documented install URL from the slug and numeric ids only", () => {
    expect(
      buildAppInstallUrl({ slug: "pgard-jadenmeister", targetId: 1001, repositoryId: 555 }),
    ).toBe(
      "https://github.com/apps/pgard-jadenmeister/installations/new/permissions?suggested_target_id=1001&repository_ids%5B%5D=555",
    );
  });

  it("encodes the repository_ids[] parameter so GitHub decodes it as an array", () => {
    const url = new URL(
      buildAppInstallUrl({ slug: "app", targetId: 42, repositoryId: 7 }) ?? "https://invalid/",
    );
    expect(url.origin).toBe("https://github.com");
    expect(url.pathname).toBe("/apps/app/installations/new/permissions");
    expect(url.searchParams.get("suggested_target_id")).toBe("42");
    expect(url.searchParams.getAll("repository_ids[]")).toEqual(["7"]);
  });

  it("refuses a non-github.com host (GHES is not supported)", () => {
    for (const webBaseUrl of [
      "https://github.example.com",
      "http://github.com",
      "https://github.com.evil.test",
    ]) {
      expect(buildAppInstallUrl({ slug: "app", targetId: 1, repositoryId: 2, webBaseUrl })).toBe(
        null,
      );
    }
  });

  it("refuses a malformed slug or ids that are not positive integers", () => {
    expect(buildAppInstallUrl({ slug: "../evil", targetId: 1, repositoryId: 2 })).toBe(null);
    expect(buildAppInstallUrl({ slug: "App", targetId: 1, repositoryId: 2 })).toBe(null);
    for (const id of [0, -1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 2]) {
      expect(buildAppInstallUrl({ slug: "app", targetId: id, repositoryId: 2 })).toBe(null);
      expect(buildAppInstallUrl({ slug: "app", targetId: 1, repositoryId: id })).toBe(null);
    }
  });
});

describe("isOpenableGitHubUrl", () => {
  it("accepts https://github.com/ URLs only", () => {
    expect(isOpenableGitHubUrl("https://github.com/login/device")).toBe(true);
    for (const url of [
      "https://github.com",
      "http://github.com/login/device",
      "https://github.com.evil.test/x",
      "https://evil.test/https://github.com/",
      "https://user:pw@github.com/x",
      "https://github.com:8443/x",
      "https://github.com/x y",
      'https://github.com/x"&calc',
      "javascript:alert(1)",
      "file:///etc/passwd",
    ]) {
      expect(isOpenableGitHubUrl(url)).toBe(false);
    }
  });
});

describe("openGitHubUrl", () => {
  const url = "https://github.com/apps/app/installations/new/permissions?suggested_target_id=1";

  it("uses a fixed argv per platform, never a shell string", () => {
    expect(openerCommandFor("darwin", url)).toEqual({ command: "open", args: [url] });
    expect(openerCommandFor("win32", url)).toEqual({ command: "explorer.exe", args: [url] });
    expect(openerCommandFor("linux", url)).toEqual({ command: "xdg-open", args: [url] });
    expect(openerCommandFor("freebsd", url)).toEqual({ command: "xdg-open", args: [url] });
  });

  it("refuses to open a non-github URL", async () => {
    const spawn = vi.fn(async () => true);
    expect(await openGitHubUrl("https://evil.test/", { platform: "darwin", spawn })).toBe(false);
    expect(openerCommandFor("linux", "https://evil.test/")).toBe(null);
    expect(spawn).not.toHaveBeenCalled();
  });

  it("passes the URL as one argument and reports a failed start as false", async () => {
    const spawn = vi.fn(async () => true);
    expect(await openGitHubUrl(url, { platform: "linux", spawn })).toBe(true);
    expect(spawn).toHaveBeenCalledWith("xdg-open", [url]);
    const failing = vi.fn(async () => {
      throw new Error("ENOENT");
    });
    expect(await openGitHubUrl(url, { platform: "linux", spawn: failing })).toBe(false);
  });
});
