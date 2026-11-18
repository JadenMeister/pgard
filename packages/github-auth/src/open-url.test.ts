import { describe, expect, it, vi } from "vitest";
import {
  detectWsl,
  isWslVersionText,
  openGitHubUrl,
  openerCommandFor,
  spawnOpener,
} from "./open-url.js";

const url = "https://github.com/login/device";

describe("WSL detection", () => {
  it("recognises the WSL1 and WSL2 kernel strings", () => {
    expect(isWslVersionText("Linux version 5.15.153.1-microsoft-standard-WSL2 (root@x)")).toBe(
      true,
    );
    expect(isWslVersionText("Linux version 4.4.0-19041-Microsoft (Microsoft@Microsoft.com)")).toBe(
      true,
    );
    expect(isWslVersionText("Linux version 6.8.0-45-generic (buildd@lcy02)")).toBe(false);
  });

  it("reads /proc/version only on Linux and treats an unreadable file as not WSL", () => {
    const read = vi.fn(() => "Linux version 5.15-microsoft-standard-WSL2");
    expect(detectWsl("linux", read)).toBe(true);
    expect(detectWsl("darwin", read)).toBe(false);
    expect(read).toHaveBeenCalledTimes(1);
    expect(
      detectWsl("linux", () => {
        throw new Error("ENOENT");
      }),
    ).toBe(false);
  });
});

describe("opener on WSL", () => {
  it("uses wslview there and xdg-open elsewhere on Linux", () => {
    expect(openerCommandFor("linux", url, process.env, true)).toEqual({
      command: "wslview",
      args: [url],
    });
    expect(openerCommandFor("linux", url, process.env, false)?.command).toBe("xdg-open");
    expect(openerCommandFor("darwin", url, process.env, true)?.command).toBe("open");
  });

  it("reports false when wslview is missing so the caller says to open the link manually", async () => {
    const spawn = vi.fn(async () => false);
    expect(await openGitHubUrl(url, { platform: "linux", isWsl: true, spawn })).toBe(false);
    expect(spawn).toHaveBeenCalledWith("wslview", [url], { checkExit: true });
  });
});

describe("spawnOpener exit status", () => {
  it("is false for a command that cannot start and for one that exits non-zero", async () => {
    expect(await spawnOpener("pgard-no-such-opener-command", [], { checkExit: true })).toBe(false);
    expect(
      await spawnOpener(process.execPath, ["-e", "process.exit(3)"], { checkExit: true }),
    ).toBe(false);
  });

  it("is true for a zero exit, and ignores the exit code without checkExit", async () => {
    expect(await spawnOpener(process.execPath, ["-e", ""], { checkExit: true })).toBe(true);
    expect(await spawnOpener(process.execPath, ["-e", "process.exit(3)"])).toBe(true);
  });
});
