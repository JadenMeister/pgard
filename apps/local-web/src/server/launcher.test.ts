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
    expect(path.basename(options.projectRoot as string)).toBe(path.basename(root));
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

  it("accepts --no-browser once, anywhere, and defaults to opening GitHub pages", async () => {
    expect((await parseLauncherArgs(["--project-root", root], async () => root)).noBrowser).toBe(
      false,
    );
    for (const argv of [
      ["--no-browser", "--project-root", root],
      ["--project-root", root, "--no-browser", "--target-port", "5173"],
    ]) {
      expect((await parseLauncherArgs(argv, async () => root)).noBrowser).toBe(true);
    }
    await expect(
      parseLauncherArgs(["--project-root", root, "--no-browser", "--no-browser"], async () => root),
    ).rejects.toBeInstanceOf(LauncherUsageError);
  });

  it("rejects a directory that is not the Git root itself", async () => {
    await expect(
      parseLauncherArgs(["--project-root", path.join(root, "sub")], async () => root),
    ).rejects.toBeInstanceOf(LauncherUsageError);
    await expect(
      parseLauncherArgs(["--project-root", root], async () => null),
    ).rejects.toBeInstanceOf(LauncherUsageError);
  });

  it("accepts --no-open and --print-url once each, in both modes (#419)", async () => {
    const fixed = await parseLauncherArgs(
      ["--project-root", root, "--print-url", "--no-open"],
      async () => root,
    );
    expect(fixed).toMatchObject({ noOpen: true, printUrl: true, noBrowser: false });
    expect(await parseLauncherArgs(["--picker", "--no-open"], async () => root)).toMatchObject({
      noOpen: true,
      printUrl: false,
    });
    for (const twice of [
      ["--picker", "--no-open", "--no-open"],
      ["--picker", "--print-url", "--print-url"],
    ]) {
      await expect(parseLauncherArgs(twice, async () => root)).rejects.toBeInstanceOf(
        LauncherUsageError,
      );
    }
  });

  it("rejects invalid target ports", async () => {
    await expect(
      parseLauncherArgs(["--project-root", root, "--target-port", "0"], async () => root),
    ).rejects.toBeInstanceOf(LauncherUsageError);
  });

  it("picker mode (pgard web) takes no path and no port, only the flags", async () => {
    const never = async (): Promise<string | null> => {
      throw new Error("no Git root is resolved in picker mode");
    };
    expect(await parseLauncherArgs(["--picker"], never)).toEqual({
      projectRoot: null,
      presetTargetPort: null,
      noBrowser: false,
      noOpen: false,
      printUrl: false,
      picker: true,
      noStore: false,
    });
    expect(
      await parseLauncherArgs(["--picker", "--no-browser", "--no-store"], never),
    ).toMatchObject({
      picker: true,
      noBrowser: true,
      noStore: true,
    });
  });

  it.each([
    [["--picker", "--project-root", "/work/x"]],
    [["--picker", "--target-port", "3000"]],
    [["--picker", "--picker"]],
    [["--no-store"]],
    [["--picker", "--no-store", "--no-store"]],
  ])("rejects %j", async (argv) => {
    await expect(parseLauncherArgs(argv, async () => root)).rejects.toBeInstanceOf(
      LauncherUsageError,
    );
  });

  it("fixed mode is never a picker", async () => {
    const options = await parseLauncherArgs(["--project-root", root], async () => root);
    expect(options).toMatchObject({ picker: false, noStore: false });
  });
});
