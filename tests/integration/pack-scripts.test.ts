import { build } from "esbuild";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { findExternalViolations, packageNameOf, shippedNotice } from "../../scripts/pack-lib.mjs";

const dirs: string[] = [];
afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

/** Bundles `source` with every bare import external, the way pack-pgard.mjs does. */
async function metafileOf(source: string) {
  const dir = mkdtempSync(path.join(tmpdir(), "pgard pack test "));
  dirs.push(dir);
  const entry = path.join(dir, "entry.mjs");
  writeFileSync(entry, source);
  const result = await build({
    entryPoints: [entry],
    outdir: path.join(dir, "out"),
    bundle: true,
    format: "esm",
    platform: "node",
    metafile: true,
    logLevel: "silent",
    plugins: [
      {
        name: "external",
        setup(b) {
          b.onResolve({ filter: /^[^./]/ }, (args) => ({ path: args.path, external: true }));
        },
      },
    ],
  });
  return result.metafile;
}

const DEPENDENCIES = { pdfkit: "0.20.2", "@napi-rs/keyring": "2.1.1" };

describe("externals check", () => {
  it("accepts declared packages (with subpaths) and node: built-ins, static or dynamic", async () => {
    const metafile = await metafileOf(`
      import fs from "node:fs";
      import PDFDocument from "pdfkit/js/pdfkit.js";
      const keyring = await import("@napi-rs/keyring");
      console.log(fs, PDFDocument, keyring);
    `);
    expect(findExternalViolations(metafile, DEPENDENCIES)).toEqual([]);
  });

  it("mutation: an undeclared static import is reported", async () => {
    const metafile = await metafileOf(`import left from "left-pad"; console.log(left);`);
    expect(findExternalViolations(metafile, DEPENDENCIES)).toEqual([
      expect.stringContaining('imports "left-pad" (import-statement)'),
    ]);
  });

  it("mutation: an undeclared dynamic import is reported", async () => {
    const metafile = await metafileOf(`const m = await import("sneaky-pkg"); console.log(m);`);
    expect(findExternalViolations(metafile, DEPENDENCIES)).toEqual([
      expect.stringContaining('imports "sneaky-pkg" (dynamic-import)'),
    ]);
  });

  it("mutation: a built-in without the node: prefix is reported", async () => {
    const metafile = await metafileOf(`import fs from "fs"; console.log(fs);`);
    expect(findExternalViolations(metafile, DEPENDENCIES)).toEqual([
      expect.stringContaining('built-in "fs" without the node: prefix'),
    ]);
  });

  it("names scoped packages and subpaths correctly", () => {
    expect(packageNameOf("@scope/pkg/deep/file.js")).toBe("@scope/pkg");
    expect(packageNameOf("pkg/deep")).toBe("pkg");
  });
});

describe("shipped NOTICE.md", () => {
  const repoNotice = readFileSync(path.join(import.meta.dirname, "../../NOTICE.md"), "utf8");

  it("points at the packed layout and keeps the repository copy unchanged", () => {
    const shipped = shippedNotice(repoNotice);
    expect(shipped).toContain("`assets/fonts/OFL.txt`");
    expect(shipped).toContain("`assets/grammars/`");
    expect(shipped).not.toContain("packages/report/fonts/PgardNoto");
    expect(shipped).not.toContain("packages/source-analysis/grammars");
    expect(repoNotice).toContain("`packages/report/fonts/OFL.txt`");
  });

  it("fails when a new repository-only path appears without a rewrite", () => {
    expect(() => shippedNotice(`${repoNotice}\nSee \`docs/NEW.md\`.\n`)).toThrow(
      /repository-only path/,
    );
  });
});
