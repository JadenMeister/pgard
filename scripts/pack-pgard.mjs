#!/usr/bin/env node
// Builds the single installable package `pgard` into .pack/ (gitignored) and packs it into
// .pack/pgard-<version>.tgz. Run `npm run build` first (`npm run pack:pgard` does both).
//
// Approach: esbuild bundles the workspace packages (@pgard/*) into a few ESM files under dist/;
// every third-party package stays an external, pinned dependency of the package. The runtime
// assets (fonts, grammars, dashboard client) are copied to assets/, and the few import.meta.url
// lookups that assume the workspace layout are rewritten to the packed layout. Every rewrite must
// match exactly once, so a refactor of those lookups fails the build instead of shipping a broken
// package. Nothing is published.
import { build } from "esbuild";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { findExternalViolations, npmCommand, shippedNotice } from "./pack-lib.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packDir = join(root, ".pack");
const stage = join(packDir, "stage");
const template = JSON.parse(readFileSync(join(root, "packaging/pgard/package.json"), "utf8"));

function fail(message) {
  console.error(`pack:pgard: ${message}`);
  process.exit(1);
}

// --- Preconditions: built output exists, versions agree, dependencies match the workspaces. ---
for (const file of [
  "apps/cli/dist/bin/pgard.js",
  "apps/local-web/dist/server/index.js",
  "apps/local-web/dist/client/index.html",
]) {
  if (!existsSync(join(root, file))) fail(`${file} is missing; run "npm run build" first`);
}
const versionSource = readFileSync(join(root, "packages/scan-core/src/version.ts"), "utf8");
const codeVersion = /PGARD_VERSION = "([^"]+)"/.exec(versionSource)?.[1];
if (codeVersion !== template.version) {
  fail(`packaging/pgard/package.json version ${template.version} != PGARD_VERSION ${codeVersion}`);
}
const workspaceDeps = new Map();
for (const group of ["apps", "packages"]) {
  for (const name of readdirSync(join(root, group))) {
    const manifest = join(root, group, name, "package.json");
    if (!existsSync(manifest)) continue;
    const json = JSON.parse(readFileSync(manifest, "utf8"));
    for (const [dep, range] of Object.entries(json.dependencies ?? {})) {
      if (!dep.startsWith("@pgard/")) workspaceDeps.set(dep, range);
    }
  }
}
if (
  JSON.stringify([...workspaceDeps].sort()) !==
  JSON.stringify(Object.entries(template.dependencies).sort())
) {
  fail(
    "dependencies in packaging/pgard/package.json differ from the workspaces' third-party " +
      `dependencies: ${JSON.stringify(Object.fromEntries(workspaceDeps))}`,
  );
}
for (const [dep, range] of Object.entries(template.dependencies)) {
  if (!/^(npm:[^@]+@)?\d+\.\d+\.\d+$/.test(range)) fail(`${dep} is not an exact version: ${range}`);
}
if (template.scripts) fail("the package must not define install scripts");

// The shrinkwrap pins the transitive tree; it must describe exactly this package's dependencies.
const shrinkwrapPath = join(root, "packaging/pgard/npm-shrinkwrap.json");
if (!existsSync(shrinkwrapPath))
  fail('npm-shrinkwrap.json is missing; run "npm run pack:shrinkwrap"');
const shrinkwrap = JSON.parse(readFileSync(shrinkwrapPath, "utf8"));
const shrinkwrapRoot = shrinkwrap.packages?.[""] ?? {};
if (
  shrinkwrap.name !== template.name ||
  shrinkwrap.version !== template.version ||
  JSON.stringify(Object.entries(shrinkwrapRoot.dependencies ?? {}).sort()) !==
    JSON.stringify(Object.entries(template.dependencies).sort())
) {
  fail(
    'npm-shrinkwrap.json is out of date with packaging/pgard/package.json; run "npm run pack:shrinkwrap"',
  );
}
for (const [location, entry] of Object.entries(shrinkwrap.packages)) {
  if (location !== "" && (!entry.resolved || !entry.integrity)) {
    fail(`npm-shrinkwrap.json entry ${location} has no resolved URL or integrity hash`);
  }
}

// --- Rewrites of workspace-layout asset lookups (each must match exactly once). ---
const rewrites = [
  {
    file: "packages/report/dist/pdf-font.js",
    from: "new URL(`../fonts/${spec.file}`, import.meta.url)",
    to: "new URL(`../assets/fonts/${spec.file}`, import.meta.url)",
  },
  {
    file: "packages/source-analysis/dist/tree-sitter/languages.js",
    from: "new URL(`../../grammars/tree-sitter-${language}.wasm`, import.meta.url)",
    to: "new URL(`../assets/grammars/tree-sitter-${language}.wasm`, import.meta.url)",
  },
  {
    file: "apps/local-web/dist/server/index.js",
    from: 'new URL("../client/", import.meta.url)',
    to: 'new URL("../assets/client/", import.meta.url)',
  },
  {
    file: "apps/cli/dist/deps.js",
    from: "import.meta.resolve(DASHBOARD_LAUNCHER_SPECIFIER)",
    to: 'new URL("./dashboard.js", import.meta.url).href',
  },
];
const rewritePlugin = {
  name: "packed-asset-paths",
  setup(b) {
    b.onLoad({ filter: /[\\/]dist[\\/].*\.js$/ }, (args) => {
      const normalized = args.path.split("\\").join("/");
      const rule = rewrites.find((r) => normalized.endsWith(`/${r.file}`));
      if (!rule) return undefined;
      const source = readFileSync(args.path, "utf8");
      if (source.split(rule.from).length !== 2) {
        fail(`expected exactly one ${JSON.stringify(rule.from)} in ${rule.file}`);
      }
      rule.done = true;
      return { contents: source.replace(rule.from, () => rule.to), loader: "js" };
    });
  },
};
// Third-party packages stay external (real dependencies); only @pgard/* and relative files bundle.
const externalPlugin = {
  name: "third-party-external",
  setup(b) {
    b.onResolve({ filter: /^[^./]/ }, (args) => {
      if (args.path.startsWith("@pgard/") || /^[A-Za-z]:[\\/]/.test(args.path)) return undefined;
      return { path: args.path, external: true };
    });
  },
};

rmSync(packDir, { recursive: true, force: true });
mkdirSync(join(stage, "dist"), { recursive: true });

const result = await build({
  entryPoints: {
    pgard: join(root, "apps/cli/dist/bin/pgard.js"),
    dashboard: join(root, "apps/local-web/dist/server/index.js"),
    "smoke-report": join(root, "packaging/smoke-report-entry.js"),
    "smoke-grammar": join(root, "packaging/smoke-grammar-entry.js"),
  },
  outdir: join(stage, "dist"),
  bundle: true,
  splitting: true,
  format: "esm",
  platform: "node",
  target: "node22",
  sourcemap: false,
  legalComments: "none",
  logLevel: "warning",
  metafile: true,
  plugins: [rewritePlugin, externalPlugin],
});
for (const rule of rewrites) if (!rule.done) fail(`rewrite for ${rule.file} was never applied`);

// Everything the bundle imports from outside itself (static, dynamic, require) must be a node:
// built-in or a declared dependency; otherwise the installed package would crash at runtime.
if (result.warnings.length > 0) fail("esbuild reported warnings (see above)");
const violations = findExternalViolations(result.metafile, template.dependencies);
if (violations.length > 0)
  fail(`undeclared externals in the bundle:\n  ${violations.join("\n  ")}`);

// --- Assets and legal files. ---
const copy = (from, to) => cpSync(join(root, from), join(stage, to), { recursive: true });
copy("apps/local-web/dist/client", "assets/client");
mkdirSync(join(stage, "assets/fonts"), { recursive: true });
for (const name of readdirSync(join(root, "packages/report/fonts"))) {
  if (name.endsWith(".ttf") || name === "OFL.txt")
    copy(`packages/report/fonts/${name}`, `assets/fonts/${name}`);
}
mkdirSync(join(stage, "assets/grammars"), { recursive: true });
for (const name of readdirSync(join(root, "packages/source-analysis/grammars"))) {
  copy(`packages/source-analysis/grammars/${name}`, `assets/grammars/${name}`);
}
for (const name of ["LICENSE", "README.md"]) copy(name, name);
// NOTICE.md names repository paths; the package layout differs (assets/fonts, assets/grammars).
writeFileSync(
  join(stage, "NOTICE.md"),
  shippedNotice(readFileSync(join(root, "NOTICE.md"), "utf8")),
);
copyFileSync(shrinkwrapPath, join(stage, "npm-shrinkwrap.json"));
writeFileSync(join(stage, "package.json"), `${JSON.stringify(template, null, 2)}\n`);

// The copied binaries must be byte-identical to the checksum-pinned sources.
const sha = (file) => createHash("sha256").update(readFileSync(file)).digest("hex");
for (const dir of ["packages/report/fonts", "packages/source-analysis/grammars"]) {
  for (const name of readdirSync(join(root, dir))) {
    if (!/\.(ttf|wasm)$/.test(name)) continue;
    const target = join(stage, "assets", dir.includes("fonts") ? "fonts" : "grammars", name);
    if (sha(join(root, dir, name)) !== sha(target)) fail(`${name} changed while copying`);
  }
}

// --- Pack (never publish). ---
const npm = npmCommand();
const packed = spawnSync(
  npm.file,
  [...npm.prefixArgs, "pack", "--pack-destination", packDir, "--json"],
  {
    cwd: stage,
    encoding: "utf8",
  },
);
if (packed.status !== 0) fail(`npm pack failed:\n${packed.stdout}\n${packed.stderr}`);
const info = JSON.parse(packed.stdout)[0];
console.log(
  `pack:pgard: ${join(".pack", info.filename)} (${info.size} bytes packed, ${info.unpackedSize} unpacked, ${info.entryCount} files)`,
);
