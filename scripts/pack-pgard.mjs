#!/usr/bin/env node
// Builds the single installable package `pgard` into .pack/ (gitignored) and packs it into
// .pack/pgard-<version>.tgz. Run `npm run build` first (`npm run pack:pgard` does both).
//
// Approach: esbuild bundles the workspace packages (@pgard/*) and the pure-JS third-party packages
// into a few ESM files under dist/ (#358), so their versions are locked when the tarball is built.
// Only @napi-rs/keyring (native) and web-tree-sitter (WASM) stay external, pinned dependencies.
// Every bundled package needs a permissive license and a license text, and NOTICE.md lists them
// all (pack-licenses.mjs). No source maps are written. The runtime
// assets (fonts, grammars, dashboard client) are copied to assets/, and the few import.meta.url
// lookups that assume the workspace layout are rewritten to the packed layout. Every rewrite must
// match exactly once, so a refactor of those lookups fails the build instead of shipping a broken
// package. Nothing is published.
import { build } from "esbuild";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { builtinModules } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  REQUIRE_BANNER,
  findDynamicCodeUses,
  findExternalViolations,
  EXTERNAL_PACKAGES,
  npmCommand,
  packageNameOf,
  shippedGrammarsReadme,
  shippedNotice,
} from "./pack-lib.mjs";
import {
  bundledPackages,
  licenseProblems,
  noticeProblems,
  packageOfInput,
  renderBundledNotice,
} from "./pack-licenses.mjs";

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
  "apps/local-web/dist/server/picker/inspector-child.js",
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
// Only the external packages (native keyring, WASM tree-sitter runtime) are dependencies of the
// published package; every other third-party dependency of the workspaces is bundled (#358).
for (const dep of EXTERNAL_PACKAGES) {
  if (!workspaceDeps.has(dep)) fail(`${dep} is external but no workspace depends on it`);
}
const externalDeps = Object.fromEntries(
  [...workspaceDeps].filter(([dep]) => EXTERNAL_PACKAGES.includes(dep)),
);
if (
  JSON.stringify(Object.entries(externalDeps).sort()) !==
  JSON.stringify(Object.entries(template.dependencies).sort())
) {
  fail(
    "dependencies in packaging/pgard/package.json must be exactly the external packages " +
      `${EXTERNAL_PACKAGES.join(", ")} with the workspaces' versions: ${JSON.stringify(externalDeps)}`,
  );
}
for (const [dep, range] of [...workspaceDeps]) {
  if (!/^(npm:[^@]+@)?\d+\.\d+\.\d+$/.test(range)) fail(`${dep} is not an exact version: ${range}`);
}
if (template.scripts) fail("the package must not define install scripts");
// Publishing metadata (docs/RELEASING.md): a manifest without it must not be packed.
if (template.private === true) fail("the package must not be private");
for (const field of ["repository", "homepage", "bugs", "license", "engines", "files", "bin"]) {
  if (template[field] === undefined) fail(`packaging/pgard/package.json has no "${field}"`);
}
if (template.repository?.url !== "git+https://github.com/JadenMeister/pgard.git") {
  fail("repository.url must be git+https://github.com/JadenMeister/pgard.git (npm provenance)");
}
if (template.publishConfig?.access !== "public" || template.publishConfig?.provenance !== true) {
  fail(
    'packaging/pgard/package.json needs publishConfig { "access": "public", "provenance": true }',
  );
}

// No npm-shrinkwrap.json on purpose (evaluated for #228, rejected for now): npm ignores it for
// installs from a tarball, and for registry installs it nests every dependency under the package
// and installs all 12 platform binaries of @napi-rs/keyring (about 25 MB instead of 588 KB). The
// two dependencies are exact pins (checked above) and everything else is bundled (#358); the only
// transitive packages left are the exact-pinned optional platform binaries of @napi-rs/keyring.

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
    // The per-file analysis worker is its own entry point (dist/source-worker.js).
    file: "packages/source-analysis/dist/file-worker.js",
    from: 'new URL("./analyze-worker.js", import.meta.url)',
    to: 'new URL("./source-worker.js", import.meta.url)',
  },
  {
    file: "apps/local-web/dist/server/index.js",
    from: 'new URL("../client/", import.meta.url)',
    to: 'new URL("../assets/client/", import.meta.url)',
  },
  {
    // The picker's inspector child process is its own entry point (dist/inspector.js).
    file: "apps/local-web/dist/server/picker/inspector-host.js",
    from: 'new URL("./inspector-child.js", import.meta.url)',
    to: 'new URL("./inspector.js", import.meta.url)',
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
// Only the native keyring and the WASM tree-sitter runtime stay external (real dependencies); every
// other third-party package is bundled so its transitive versions are locked at release time.
const externalPlugin = {
  name: "third-party-external",
  setup(b) {
    b.onResolve({ filter: /^[^./]/ }, (args) => {
      if (/^[A-Za-z]:[\\/]/.test(args.path)) return undefined;
      return EXTERNAL_PACKAGES.includes(packageNameOf(args.path))
        ? { path: args.path, external: true }
        : undefined;
    });
  },
};

// pdfkit loads its 14 standard-font metrics with `createRequire(import.meta.url)("#standard-fonts/X")`,
// a package-imports lookup that cannot work once pdfkit is inlined into dist/. Turn the 14 calls
// into plain `require("#standard-fonts/X")`, which esbuild resolves through pdfkit's own "imports"
// map and bundles. Each pattern must match exactly as often as expected, or the build fails.
const pdfkitPlugin = {
  name: "pdfkit-standard-fonts",
  setup(b) {
    b.onLoad({ filter: /[\\/]pdfkit[\\/]js[\\/]pdfkit\.node\.mjs$/ }, (args) => {
      let source = readFileSync(args.path, "utf8");
      const edit = (pattern, to, expected) => {
        const count = [...source.matchAll(pattern)].length;
        if (count !== expected) fail(`pdfkit: expected ${expected} x ${pattern}, found ${count}`);
        source = source.replace(pattern, to);
      };
      edit(/^import \{ createRequire \} from 'module';\n/gm, "", 1);
      edit(/^const require\$1 = createRequire\(import\.meta\.url\);\n/gm, "", 1);
      edit(/require\$1\('(#standard-fonts\/\w+)'\)/g, "require('$1')", 14);
      if (/createRequire|require\$1/.test(source)) fail("pdfkit: createRequire is still used");
      return { contents: source, loader: "js", resolveDir: dirname(args.path) };
    });
  },
};

// @vue/compiler-sfc's CommonJS build requires optional template engines (pug, ejs, handlebars,
// react-dom/server, ...) by name for `<template lang="...">` preprocessing, which PGARD never uses
// (it only calls `parse`). Inside that package's dist/, a require of anything that is neither a
// built-in nor one of its declared dependencies becomes a module that throws the "Cannot find
// module" error compiler-sfc already expects, so nothing unrelated (a dev dependency of this
// repository that happens to be installed) is pulled into the bundle. Elsewhere nothing is stubbed.
const sfcDependencies = new Set(
  Object.keys(
    JSON.parse(readFileSync(join(root, "node_modules/@vue/compiler-sfc/package.json"), "utf8"))
      .dependencies,
  ),
);
const absentOptionalPlugin = {
  name: "compiler-sfc-optional-engines",
  setup(b) {
    b.onResolve({ filter: /^[^./]/ }, (args) => {
      if (args.kind !== "require-call") return undefined;
      // TypeScript's optional `--enableSourceMaps` hook, in a try block; the package is not installed.
      if (
        args.path === "source-map-support" &&
        /[\\/]typescript-api[\\/]lib[\\/]/.test(args.importer)
      )
        return { path: args.path, namespace: "absent-optional" };
      if (!/[\\/]@vue[\\/]compiler-sfc[\\/]dist[\\/]/.test(args.importer)) return undefined;
      const name = packageNameOf(args.path.replace(/^node:/, ""));
      if (sfcDependencies.has(name) || builtinModules.includes(name)) return undefined;
      return { path: args.path, namespace: "absent-optional" };
    });
    b.onLoad({ filter: /.*/, namespace: "absent-optional" }, (args) => ({
      contents: `throw Object.assign(new Error(${JSON.stringify(`Cannot find module '${args.path}'`)}), { code: "MODULE_NOT_FOUND" });`,
      loader: "js",
    }));
  },
};

// Hardening: a bundled third-party module may only import (or require) a package that its own
// package.json declares (dependencies, optionalDependencies, peerDependencies), a built-in, one of
// the two externals, or itself. Anything else is a phantom dependency that only resolved because
// of how this repository happens to be installed, and would resolve differently after an upgrade.
// It fails the pack with a list instead of bundling it. (The stubs above and the externals are
// decided before this plugin runs.)
const undeclaredImports = [];
const manifestCache = new Map();
const declaredBy = (dir) => {
  if (!manifestCache.has(dir)) {
    const manifest = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    manifestCache.set(
      dir,
      new Set([
        manifest.name,
        ...Object.keys(manifest.dependencies ?? {}),
        ...Object.keys(manifest.optionalDependencies ?? {}),
        ...Object.keys(manifest.peerDependencies ?? {}),
      ]),
    );
  }
  return manifestCache.get(dir);
};
const declaredDependencyPlugin = {
  name: "declared-dependencies-only",
  setup(b) {
    b.onResolve({ filter: /^[^./#]/ }, (args) => {
      if (/^[A-Za-z]:[\\/]/.test(args.path) || args.path.startsWith("node:")) return undefined;
      const importer = packageOfInput(args.importer);
      if (importer === null || importer.name.startsWith("@pgard/")) return undefined;
      const name = packageNameOf(args.path);
      if (builtinModules.includes(name) || declaredBy(importer.dir).has(name)) return undefined;
      // typescript-api is the npm alias of typescript: its manifest names itself "typescript".
      undeclaredImports.push(`${importer.name} imports "${args.path}" (${args.kind})`);
      return undefined;
    });
  },
};

rmSync(packDir, { recursive: true, force: true });
mkdirSync(join(stage, "dist"), { recursive: true });

const result = await build({
  entryPoints: {
    pgard: join(root, "apps/cli/dist/bin/pgard.js"),
    dashboard: join(root, "apps/local-web/dist/server/index.js"),
    inspector: join(root, "apps/local-web/dist/server/picker/inspector-child.js"),
    "smoke-report": join(root, "packaging/smoke-report-entry.js"),
    "smoke-grammar": join(root, "packaging/smoke-grammar-entry.js"),
    "source-worker": join(root, "packages/source-analysis/dist/analyze-worker.js"),
  },
  absWorkingDir: root,
  outdir: join(stage, "dist"),
  bundle: true,
  splitting: true,
  format: "esm",
  platform: "node",
  target: "node22",
  // Bundled CommonJS (typescript, @vue/compiler-sfc, postcss) calls require() on node: built-ins.
  banner: { js: REQUIRE_BANNER },
  // Vue's CommonJS entry picks its production or development build at run time; pick one.
  define: { "process.env.NODE_ENV": '"production"' },
  sourcemap: false,
  // Keep the `/*!` and `@license` banners (TypeScript's Apache header, brotli's header) in dist/.
  legalComments: "eof",
  logLevel: "warning",
  metafile: true,
  plugins: [
    rewritePlugin,
    externalPlugin,
    pdfkitPlugin,
    absentOptionalPlugin,
    declaredDependencyPlugin,
  ],
});
for (const rule of rewrites) if (!rule.done) fail(`rewrite for ${rule.file} was never applied`);
if (undeclaredImports.length > 0) {
  fail(
    `bundled code imports packages its own package.json does not declare:\n  ${[...new Set(undeclaredImports)].join("\n  ")}`,
  );
}

// Everything the bundle imports from outside itself (static, dynamic, require) must be a node:
// built-in or a declared dependency; otherwise the installed package would crash at runtime.
if (result.warnings.length > 0) fail("esbuild reported warnings (see above)");
const dynamicUses = readdirSync(join(stage, "dist"))
  .filter((name) => name.endsWith(".js"))
  .flatMap((name) =>
    findDynamicCodeUses(`dist/${name}`, readFileSync(join(stage, "dist", name), "utf8")),
  );
if (dynamicUses.length > 0)
  fail(`unverifiable module loading in the bundle:\n  ${dynamicUses.join("\n  ")}`);
const violations = findExternalViolations(result.metafile, template.dependencies, {
  allowBareBuiltins: true,
});
if (violations.length > 0)
  fail(`undeclared externals in the bundle:\n  ${violations.join("\n  ")}`);

// Every bundled third-party package needs a permissive license and a license text (#358).
const bundled = bundledPackages(result.metafile, root);
const licenseIssues = licenseProblems(bundled);
if (licenseIssues.length > 0) fail(`bundled package licenses:\n  ${licenseIssues.join("\n  ")}`);
console.log(`pack:pgard: ${bundled.length} third-party packages bundled, all permissive`);

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
  name === "README.md"
    ? writeFileSync(
        join(stage, "assets/grammars/README.md"),
        shippedGrammarsReadme(
          readFileSync(join(root, "packages/source-analysis/grammars", name), "utf8"),
        ),
      )
    : copy(`packages/source-analysis/grammars/${name}`, `assets/grammars/${name}`);
}
for (const name of ["LICENSE", "README.md"]) copy(name, name);
// NOTICE.md names repository paths; the package layout differs (assets/fonts, assets/grammars).
const bundledNotice = renderBundledNotice(bundled);
const noticeIssues = noticeProblems(bundled, bundledNotice);
if (noticeIssues.length > 0) fail(`NOTICE.md:\n  ${noticeIssues.join("\n  ")}`);
writeFileSync(
  join(stage, "NOTICE.md"),
  `${shippedNotice(readFileSync(join(root, "NOTICE.md"), "utf8")).trimEnd()}\n\n${bundledNotice}`,
);
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
