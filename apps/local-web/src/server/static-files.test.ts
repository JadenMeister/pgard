import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadStaticAssets } from "./static-files.js";

describe("loadStaticAssets", () => {
  let root: string;
  beforeEach(async () => {
    root = await mkdtemp(path.join(os.tmpdir(), "pgard-static-"));
  });
  afterEach(async () => {
    await rm(root, { recursive: true, force: true });
  });

  it("maps only known asset types to exact URLs, with / as index.html", async () => {
    const client = path.join(root, "client");
    await mkdir(path.join(client, "assets"), { recursive: true });
    await writeFile(path.join(client, "index.html"), "<html></html>");
    await writeFile(path.join(client, "assets", "app.js"), "console.log(1)");
    await writeFile(path.join(client, "assets", "app.css"), "body{}");
    await writeFile(path.join(client, "assets", "app.js.map"), "{}");
    await writeFile(path.join(client, ".env"), "SECRET=1");
    await writeFile(path.join(client, "notes.txt"), "x");
    await writeFile(path.join(root, "outside.js"), "outside");
    await symlink(path.join(root, "outside.js"), path.join(client, "assets", "link.js"));

    const assets = await loadStaticAssets(client);
    expect([...assets.keys()].sort()).toEqual([
      "/",
      "/assets/app.css",
      "/assets/app.js",
      "/index.html",
    ]);
    expect(assets.get("/")?.contentType).toBe("text/html; charset=utf-8");
    expect(assets.get("/assets/app.js")?.contentType).toBe("text/javascript; charset=utf-8");
  });

  it("returns an empty map when the client was not built", async () => {
    expect((await loadStaticAssets(path.join(root, "missing"))).size).toBe(0);
  });
});
