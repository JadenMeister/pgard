import { describe, expect, it, vi } from "vitest";
import { OPENER_GRACE_MS, WSLVIEW_PATHS, isWsl, openGitHubUrl, spawnOpener } from "./open-url.js";

const URL_TO_OPEN = "https://github.com/login/device";
const wslKernel = async (file: string): Promise<string> => {
  if (file === "/proc/sys/kernel/osrelease") return "5.15.90.1-microsoft-standard-WSL2";
  throw new Error("ENOENT");
};
const plainKernel = async (): Promise<string> => "6.8.0-generic";
const unreadable = async (): Promise<string> => {
  throw new Error("ENOENT");
};

describe("isWsl", () => {
  it("detects a microsoft kernel in osrelease or /proc/version, case-insensitively", async () => {
    expect(await isWsl(wslKernel)).toBe(true);
    const onlyVersion = async (file: string): Promise<string> => {
      if (file === "/proc/version") return "Linux version 4.4.0-19041-Microsoft (gcc)";
      throw new Error("ENOENT");
    };
    expect(await isWsl(onlyVersion)).toBe(true);
  });

  it("is false for another kernel or when nothing can be read", async () => {
    expect(await isWsl(plainKernel)).toBe(false);
    expect(await isWsl(unreadable)).toBe(false);
  });
});

describe("openGitHubUrl on WSL", () => {
  it("tries wslview from fixed absolute paths, never xdg-open or a PATH lookup", async () => {
    const spawn = vi.fn(async () => true);
    const options = { platform: "linux", spawn, readText: wslKernel } as const;
    expect(await openGitHubUrl(URL_TO_OPEN, options)).toBe(true);
    expect(spawn).toHaveBeenCalledTimes(1);
    expect(spawn).toHaveBeenCalledWith("/usr/bin/wslview", [URL_TO_OPEN]);
    for (const path of WSLVIEW_PATHS) expect(path.startsWith("/")).toBe(true);
  });

  it("tries the next fixed path, then reports false so the caller prints the manual note", async () => {
    const second = vi.fn(async (command: string) => command === "/usr/local/bin/wslview");
    expect(
      await openGitHubUrl(URL_TO_OPEN, { platform: "linux", spawn: second, readText: wslKernel }),
    ).toBe(true);
    const none = vi.fn(async (_command: string, _args: readonly string[]) => false);
    expect(
      await openGitHubUrl(URL_TO_OPEN, { platform: "linux", spawn: none, readText: wslKernel }),
    ).toBe(false);
    expect(none.mock.calls.map((call) => call[0])).toEqual([...WSLVIEW_PATHS]);
  });

  it("uses xdg-open on plain Linux and never reads the kernel files elsewhere", async () => {
    const spawn = vi.fn(async () => true);
    expect(
      await openGitHubUrl(URL_TO_OPEN, { platform: "linux", spawn, readText: plainKernel }),
    ).toBe(true);
    expect(spawn).toHaveBeenCalledWith("xdg-open", [URL_TO_OPEN]);
    const readText = vi.fn(plainKernel);
    await openGitHubUrl(URL_TO_OPEN, { platform: "darwin", spawn, readText });
    expect(readText).not.toHaveBeenCalled();
  });

  it("opens nothing for a non-github URL", async () => {
    const spawn = vi.fn(async () => true);
    expect(
      await openGitHubUrl("https://evil.test/", { platform: "linux", spawn, readText: wslKernel }),
    ).toBe(false);
    expect(spawn).not.toHaveBeenCalled();
  });
});

describe("spawnOpener exit handling", () => {
  it("has a short grace period", () => {
    expect(OPENER_GRACE_MS).toBeLessThanOrEqual(3000);
  });

  it("reports a non-zero exit as a failure and a zero exit as opened", async () => {
    const node = process.execPath;
    expect(await spawnOpener(node, ["-e", "process.exit(3)"])).toBe(false);
    expect(await spawnOpener(node, ["-e", "process.exit(0)"])).toBe(true);
  });

  it("reports a command that cannot start as a failure", async () => {
    expect(await spawnOpener("/nonexistent/pgard-opener", [])).toBe(false);
  });
});
