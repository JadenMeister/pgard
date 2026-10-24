import { mkdtemp, mkdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { LauncherUsageError, parseLauncherArgs } from "./launcher.js";

describe("parseLauncherArgs", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(path.join(os.tmpdir(), "pgard-launcher-"));
    await mkdir(path.join(root, "sub"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("accepts an absolute Git root and an optional target port", async () => {
    const options = await parseLauncherArgs(
      ["--project-root", root, "--target-port", "5173"],
      async () => root,
    );
    expect(options.presetTargetPort).toBe(5173);
    expect(path.basename(options.projectRoot)).toBe(path.basename(root));
  });

  it.each([
    [["--project-root", "relative/path"]],
    [["--target-port", "3000"]],
    [["--project-root"]],
    [["--unknown", "x"]],
  ])("rejects %j", async (argv) => {
    await expect(parseLauncherArgs(argv, async () => root)).rejects.toBeInstanceOf(
      LauncherUsageError,
    );
  });

  it("rejects a directory that is not the Git root itself", async () => {
    await expect(
      parseLauncherArgs(["--project-root", path.join(root, "sub")], async () => root),
    ).rejects.toBeInstanceOf(LauncherUsageError);
    await expect(
      parseLauncherArgs(["--project-root", root], async () => null),
    ).rejects.toBeInstanceOf(LauncherUsageError);
  });

  it("rejects invalid target ports", async () => {
    await expect(
      parseLauncherArgs(["--project-root", root, "--target-port", "0"], async () => root),
    ).rejects.toBeInstanceOf(LauncherUsageError);
  });
});
