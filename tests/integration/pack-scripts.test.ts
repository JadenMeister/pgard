import { build } from "esbuild";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  EXTERNAL_PACKAGES,
  REQUIRE_BANNER,
  findDynamicCodeUses,
  findExternalViolations,
  packageNameOf,
  shippedGrammarsReadme,
  shippedNotice,
} from "../../scripts/pack-lib.mjs";
import {
  ALLOWED_LICENSES,
  bundledPackages,
  declaredLicense,
  isAllowedExpression,
  licenseProblems,
  packageOfInput,
  renderBundledNotice,
} from "../../scripts/pack-licenses.mjs";

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
          b.onResolve({ filter: /^[^./]/ }, (args) =>
            // Absolute Windows paths (the entry point) are files, not packages.
            /^[A-Za-z]:[\\/]/.test(args.path) ? undefined : { path: args.path, external: true },
          );
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

describe("unverifiable module loading", () => {
  it("accepts literal dynamic imports", () => {
    expect(
      findDynamicCodeUses("a.js", 'const m = () => import("@napi-rs/keyring"); import(`x`);'),
    ).toEqual([]);
  });

  it.each([
    ["import(process.env.X)", "non-literal"],
    ['import("@vue/" + x)', "non-literal"],
    ["import(`@vue/${x}`)", "non-literal"],
    ['createRequire(import.meta.url)("left-pad")', "createRequire"],
  ])("mutation: %s is reported", (code, what) => {
    const found = findDynamicCodeUses("a.js", `\n${code};`);
    expect(found).toHaveLength(1);
    expect(found[0]).toContain("a.js:2");
    expect(found[0]).toContain(what);
  });
});

describe("unverifiable module loading in bundled third-party code", () => {
  const module = (name: string, body: string) => `// ${name}\n${body}`;

  it("accepts the banner and literal built-in requires", () => {
    const code = `${REQUIRE_BANNER}\n${module("node_modules/x/index.js", 'var fs = __require("fs");')}`;
    expect(findDynamicCodeUses("a.js", code)).toEqual([]);
  });

  it("mutation: a computed require in a package without an allowlist entry is reported", () => {
    const found = findDynamicCodeUses(
      "a.js",
      module("node_modules/evil/index.js", "var m = __require(process.env.X);"),
    );
    expect(found).toEqual([expect.stringContaining("require() with a non-literal specifier")]);
    expect(found[0]).toContain("node_modules/evil/index.js");
  });

  it("mutation: __dirname in a third-party module is reported, not in first-party code", () => {
    expect(
      findDynamicCodeUses("a.js", module("node_modules/x/i.js", "read(__dirname + '/f');")),
    ).toHaveLength(1);
    expect(
      findDynamicCodeUses("a.js", module("packages/report/dist/a.js", "read(import.meta.url);")),
    ).toEqual([]);
  });

  it("an allowlist entry matches its module and line only", () => {
    const allowed = [{ module: "x/i.js", line: /ICC/, why: "test" }];
    const code = (line: string, name = "node_modules/x/i.js") => module(name, line);
    expect(findDynamicCodeUses("a.js", code("new URL(ICC, import.meta.url)"), allowed)).toEqual([]);
    expect(
      findDynamicCodeUses("a.js", code("new URL(other, import.meta.url)"), allowed),
    ).toHaveLength(1);
    expect(
      findDynamicCodeUses(
        "a.js",
        code("new URL(ICC, import.meta.url)", "node_modules/y/i.js"),
        allowed,
      ),
    ).toHaveLength(1);
  });

  it("keeps the native and WASM packages external", () => {
    expect(EXTERNAL_PACKAGES).toEqual(["@napi-rs/keyring", "web-tree-sitter"]);
  });
});

describe("bundled package licenses", () => {
  it("accepts permissive SPDX expressions and rejects the rest", () => {
    for (const ok of [
      "MIT",
      "ISC",
      "BSD-2-Clause",
      "BSD-3-Clause",
      "Apache-2.0",
      "0BSD",
      "BlueOak-1.0.0",
      "CC0-1.0",
      "Python-2.0",
      "(MIT OR GPL-3.0)",
      "(MIT AND Apache-2.0)",
      "(GPL-3.0 OR (MIT AND ISC))",
    ]) {
      expect(isAllowedExpression(ok), ok).toBe(true);
    }
    for (const bad of [
      "GPL-3.0",
      "LGPL-2.1-or-later",
      "AGPL-3.0",
      "MPL-2.0",
      "SSPL-1.0",
      "UNLICENSED",
      "SEE LICENSE IN LICENSE.md",
      "(MIT AND GPL-3.0)",
      "MIT WITH Classpath-exception-2.0",
      "(MIT",
      "",
    ]) {
      expect(isAllowedExpression(bad), bad).toBe(false);
    }
    expect(ALLOWED_LICENSES).toContain("MIT");
  });

  it("reads the declared license in its three forms", () => {
    expect(declaredLicense({ license: "MIT" })).toBe("MIT");
    expect(declaredLicense({ license: { type: "ISC" } })).toBe("ISC");
    expect(declaredLicense({ licenses: [{ type: "MIT" }, { type: "Apache-2.0" }] })).toBe(
      "(MIT OR Apache-2.0)",
    );
    expect(declaredLicense({})).toBeNull();
  });

  it("finds the package of a bundled input, including nested and scoped ones", () => {
    expect(packageOfInput("node_modules/pdfkit/js/a.mjs")).toEqual({
      name: "pdfkit",
      dir: "node_modules/pdfkit",
    });
    expect(packageOfInput("node_modules/a/node_modules/@s/b/lib/x.js")).toEqual({
      name: "@s/b",
      dir: "node_modules/a/node_modules/@s/b",
    });
    expect(packageOfInput("packages/report/dist/a.js")).toBeNull();
  });

  /** A fake repository root with node_modules packages and a metafile that bundles them. */
  function fixture(packages: Record<string, { manifest: object; files?: Record<string, string> }>) {
    const root = mkdtempSync(path.join(tmpdir(), "pgard license test "));
    dirs.push(root);
    const inputs: Record<string, { bytesInOutput: number }> = {};
    for (const [name, { manifest, files = {} }] of Object.entries(packages)) {
      const dir = path.join(root, "node_modules", name);
      mkdirSync(dir, { recursive: true });
      writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name, ...manifest }));
      for (const [file, text] of Object.entries(files)) writeFileSync(path.join(dir, file), text);
      inputs[`node_modules/${name}/index.js`] = { bytesInOutput: 10 };
    }
    inputs["node_modules/@pgard/x/index.js"] = { bytesInOutput: 10 };
    inputs["node_modules/unused/index.js"] = { bytesInOutput: 0 };
    return { root, metafile: { outputs: { "out.js": { inputs } } } };
  }

  it("lists bundled packages, skips workspace and tree-shaken ones, and renders their texts", () => {
    const { root, metafile } = fixture({
      good: {
        manifest: { version: "1.0.0", license: "MIT" },
        files: { LICENSE: "MIT text A\r\n" },
      },
      twin: { manifest: { version: "2.0.0", license: "MIT" }, files: { LICENSE: "MIT text A" } },
      "@s/scoped": {
        manifest: { version: "3.1.0", license: "ISC" },
        files: { "LICENSE.md": "ISC text", NOTICE: "Notice text" },
      },
    });
    const packages = bundledPackages(metafile, root, {});
    expect(packages.map((pkg) => `${pkg.name}@${pkg.version}`)).toEqual([
      "@s/scoped@3.1.0",
      "good@1.0.0",
      "twin@2.0.0",
    ]);
    expect(licenseProblems(packages)).toEqual([]);
    const notice = renderBundledNotice(packages);
    expect(notice).toContain("- good 1.0.0 (MIT)\n- twin 2.0.0 (MIT)");
    expect(notice.match(/MIT text A/g)).toHaveLength(1);
    expect(notice).toContain("ISC text");
    expect(notice).toContain("Notice text");
  });

  it("mutation: a missing license text, a missing license and a copyleft license fail the pack", () => {
    const { root, metafile } = fixture({
      nofile: { manifest: { version: "1.0.0", license: "MIT" } },
      nolicense: { manifest: { version: "1.0.0" }, files: { LICENSE: "text" } },
      copyleft: { manifest: { version: "1.0.0", license: "GPL-3.0" }, files: { COPYING: "GPL" } },
    });
    expect(licenseProblems(bundledPackages(metafile, root, {}))).toEqual([
      expect.stringContaining('copyleft@1.0.0 has license "GPL-3.0"'),
      expect.stringContaining("nofile@1.0.0 has no license file"),
      expect.stringContaining("nolicense@1.0.0 declares no license"),
    ]);
  });

  it("a reviewed override covers exactly its version and nothing else", () => {
    const overrides = { "odd@1.0.0": { license: "MIT", text: "reviewed text" } };
    const covered = fixture({ odd: { manifest: { version: "1.0.0" } } });
    const packages = bundledPackages(covered.metafile, covered.root, overrides);
    expect(licenseProblems(packages)).toEqual([]);
    expect(renderBundledNotice(packages)).toContain("reviewed text");
    const bumped = fixture({ odd: { manifest: { version: "1.0.1" } } });
    expect(licenseProblems(bundledPackages(bumped.metafile, bumped.root, overrides))).toHaveLength(
      2,
    );
  });
});

describe("shipped grammars README", () => {
  it("labels the source file as a repository path", () => {
    const readme = readFileSync(
      path.join(import.meta.dirname, "../../packages/source-analysis/grammars/README.md"),
      "utf8",
    );
    const shipped = shippedGrammarsReadme(readme);
    expect(shipped).toContain("in the source repository");
    expect(shipped).not.toContain("(`src/tree-sitter/languages.ts`)");
  });
});
