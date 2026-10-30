// Helpers shared by pack-pgard.mjs and smoke-pack.mjs (and unit-tested in
// tests/integration/pack-scripts.test.ts). Plain Node, no dependencies.
import { existsSync } from "node:fs";
import { builtinModules } from "node:module";
import { dirname, join } from "node:path";

/**
 * How to run npm without a shell. On Windows `npm.cmd` needs `shell: true`, which joins arguments
 * without quoting (a path with a space breaks). Running npm's own `npm-cli.js` through the current
 * Node needs neither the shell nor quoting. Returns `{ file, prefixArgs }` for `spawnSync`.
 */
export function npmCommand() {
  if (process.platform !== "win32") return { file: "npm", prefixArgs: [] };
  const fromEnv = process.env.npm_execpath;
  const nodeDir = dirname(process.execPath);
  const candidates = [
    ...(fromEnv && /npm-cli\.js$/.test(fromEnv) ? [fromEnv] : []),
    join(nodeDir, "node_modules", "npm", "bin", "npm-cli.js"),
  ];
  const cli = candidates.find((candidate) => existsSync(candidate));
  if (cli === undefined) {
    throw new Error(`cannot find npm-cli.js (looked in ${candidates.join(", ")})`);
  }
  return { file: process.execPath, prefixArgs: [cli] };
}

/** Third-party packages that stay real dependencies: native code and WASM that cannot be inlined. */
export const EXTERNAL_PACKAGES = ["@napi-rs/keyring", "web-tree-sitter"];

/**
 * Prelude of every bundled file. Bundled CommonJS (typescript, @vue/compiler-sfc, postcss) calls
 * `require()` on node: built-ins and reads `__filename`/`__dirname`, none of which exist in an ES
 * module. It is the only `createRequire` allowed in the output (see `findDynamicCodeUses`).
 */
export const REQUIRE_BANNER =
  'import { createRequire as __pgardCreateRequire } from "node:module"; import { fileURLToPath as __pgardFileURLToPath } from "node:url"; import { dirname as __pgardDirname } from "node:path"; const require = __pgardCreateRequire(import.meta.url); const __filename = __pgardFileURLToPath(import.meta.url); const __dirname = __pgardDirname(__filename);';

/** Package name of a bare import specifier: `a/b` is `a`, `@s/a/b` is `@s/a`. */
export function packageNameOf(specifier) {
  const parts = specifier.split("/");
  return specifier.startsWith("@") ? parts.slice(0, 2).join("/") : (parts[0] ?? specifier);
}

/**
 * Checks an esbuild metafile: every external import of every output file (static, dynamic and
 * `require`) must be a `node:` built-in or a package listed in `dependencies`. Returns one
 * message per violation; empty means the bundle only needs what the package declares.
 * `allowBareBuiltins` accepts `fs` for `node:fs` (bundled CommonJS uses the bare names).
 * Imports whose specifier is not a string literal are invisible to the metafile; those are
 * caught by `findDynamicCodeUses` on the bundle text.
 */
export function findExternalViolations(metafile, dependencies, { allowBareBuiltins = false } = {}) {
  const allowed = new Set(Object.keys(dependencies));
  const violations = [];
  for (const [output, info] of Object.entries(metafile.outputs)) {
    for (const entry of info.imports) {
      if (!entry.external) continue;
      const specifier = entry.path;
      if (specifier.startsWith("node:")) continue;
      if (builtinModules.includes(specifier)) {
        if (allowBareBuiltins) continue;
        violations.push(
          `${output} imports the built-in "${specifier}" without the node: prefix (${entry.kind})`,
        );
        continue;
      }
      if (!allowed.has(packageNameOf(specifier))) {
        violations.push(
          `${output} imports "${specifier}" (${entry.kind}), which is not a dependency of the package`,
        );
      }
    }
  }
  return violations;
}

/**
 * Bundled third-party code that loads modules or files by a computed path. Each entry names the
 * module (a substring of the `// node_modules/...` path esbuild writes above each module), a
 * pattern for the exact line, and why it cannot run in PGARD. Anything not listed fails the pack.
 */
export const ALLOWED_DYNAMIC_USES = [
  {
    module: "typescript-api/lib/typescript.js",
    line: /__require\(modulePath\)/,
    why: "ts.sys.require loads tsserver plugins; PGARD only parses in memory (createSourceFile, createProgram with an in-memory host)",
  },
  {
    module: "typescript-api/lib/typescript.js",
    line: /host\.require\(|= require\(\$\{|_require_/,
    why: "language-service plugin loading and generated-code text; not reachable from createSourceFile or the in-memory createProgram",
  },
  {
    module: "@vue/compiler-core/dist/",
    line: /require\(\$\{JSON\.stringify\(runtimeModuleName\)\}\)/,
    why: "text of generated SSR render code (a string), not a require call of the scanner",
  },
  {
    module: "typescript-api/lib/typescript.js",
    line: /__require\("source-map-support"\)/,
    why: "optional, in a try block, only behind tsc --enableSourceMaps",
  },
  {
    module: "typescript-api/lib/typescript.js",
    line: /__filename|__dirname|typeof __require/,
    why: "locates tsc's own lib files and test hooks; PGARD sets noLib and reads nothing from disk through TypeScript",
  },
  {
    module: "typescript-api/lib/typescript.js",
    line: /import_meta|import\.meta|import\(|createRequire/,
    why: "diagnostic message text and code printing about import()/import.meta in the scanned source, not module loading",
  },
  {
    module: "@babel/parser/lib/index.js",
    line: /import\(|import\.meta/,
    why: "parser error text about import() and import.meta",
  },
  {
    module: "@vue/compiler-sfc/dist/compiler-sfc.cjs.js",
    line: /:import\(|import\.meta|__require\.cache|__require\.resolve|load = __require|__dirname|__filename/,
    why: "CSS ':import()' selector text; CSS preprocessor loading (scss, less, stylus) and postcss source-map handling that parse() never reaches",
  },
  {
    module: "postcss/",
    line: /__require|__dirname|__filename|import\.meta/,
    why: "postcss reads previous source maps and plugin config from disk; compiler-sfc's parse() never calls it",
  },
  {
    module: "pdfkit/js/pdfkit.node.mjs",
    line: /ICC_PROFILE_PATH/,
    why: "sRGB profile for PDF/A output only; PGARD does not request a PDF/A subset",
  },
];

/**
 * Scans bundle text for module or file loading that bundling would break or the metafile cannot
 * see: `import(` with a non-literal argument, `require(` with a non-literal argument, `createRequire`
 * (except the banner), `require.cache`/`require.resolve`, and `__dirname`, `__filename` and
 * `import.meta` in third-party modules. A hit is accepted only if `allowed` has an entry for the
 * module and line. Returns one message per unaccepted use.
 */
export function findDynamicCodeUses(file, code, allowed = ALLOWED_DYNAMIC_USES) {
  const found = [];
  const lines = code.split(REQUIRE_BANNER).join("").split("\n");
  let owner = "";
  const literalArgument = /^\s*(?:"[^"\\\n]*"|'[^'\\\n]*'|`[^`$\\]*`)\s*[,)]/;
  lines.forEach((text, index) => {
    const header = /^\/\/ ((?:node_modules|packages|apps)\/\S+)$/.exec(text);
    if (header !== null) owner = header[1];
    const report = (what) => {
      if (allowed.some((entry) => owner.includes(entry.module) && entry.line.test(text))) return;
      found.push(`${file}:${index + 1} ${what}${owner === "" ? "" : ` (in ${owner})`}`);
    };
    for (const match of text.matchAll(/\b(?:import|(?:__)?require)\s*\(/g)) {
      if (!literalArgument.test(text.slice(match.index + match[0].length))) {
        report(
          `has ${match[0].startsWith("import") ? "import()" : "require()"} with a non-literal specifier`,
        );
      }
    }
    if (/\bcreateRequire\b/.test(text)) report("uses createRequire");
    if (/\b__?require\.(?:cache|resolve|main|extensions)\b/.test(text)) {
      report("uses require.cache/resolve");
    }
    if (/\b__(?:dirname|filename)\b|\bimport\.meta\b/.test(text)) {
      // PGARD's own modules (packages/..., apps/...) are covered by the asset rewrites and smoke test.
      if (owner.startsWith("node_modules/")) {
        report("reads __dirname, __filename or import.meta in a third-party module");
      }
    }
  });
  return found;
}

/**
 * Rewrites the grammars README for the packed layout: the pinned checksums live in the code
 * (`GRAMMAR_SHA256`), which is compiled into dist/, not in a source file the package ships.
 */
export function shippedGrammarsReadme(text) {
  const from = "(`src/tree-sitter/languages.ts`)";
  if (!text.includes(from)) throw new Error("grammars README no longer names languages.ts");
  const out = text
    .split(from)
    .join(
      "(compiled into `dist/`; source: `packages/source-analysis/src/tree-sitter/languages.ts` in the source repository)",
    );
  return out;
}

/**
 * Rewrites the repository NOTICE.md for the packed layout, where the fonts live in `assets/fonts/`
 * and the grammars in `assets/grammars/`. Throws unless every repo path is either rewritten to
 * a file the package ships or removed, so the shipped copy never points at a path that is absent.
 */
export function shippedNotice(text) {
  let out = text;
  const replaceAll = (from, to) => {
    if (!out.includes(from))
      throw new Error(`NOTICE.md no longer contains ${JSON.stringify(from)}`);
    out = out.split(from).join(to);
  };
  replaceAll("`packages/report/fonts/", "`assets/fonts/");
  // The recipe is not shipped: name it as a repository file instead of a broken package path.
  replaceAll(
    "`assets/fonts/subset.py`",
    "`packages/report/fonts/subset.py` in the source repository, not shipped here",
  );
  replaceAll("`packages/source-analysis/grammars/`", "`assets/grammars/`");
  replaceAll(
    "(sources, versions and SHA-256 in its\n`README.md`, checked by a test)",
    "(sources, versions and SHA-256 in its\n`README.md`, and checked again every time a grammar is loaded)",
  );
  // The reference data is compiled into dist/; its source paths exist only in the repository.
  replaceAll(
    "The data lives in `packages/findings/src/standards/`.",
    "The data is compiled into this package (source: `packages/findings/src/standards/` in the source repository).",
  );
  replaceAll(
    "([docs/RULE_MAPPING.md](docs/RULE_MAPPING.md))",
    "(`docs/RULE_MAPPING.md` in the source repository)",
  );
  for (const script of ["generate-cert-java.mjs", "generate-owasp-mapped-cwes.mjs"]) {
    replaceAll(
      `\`packages/findings/scripts/${script}\``,
      `\`packages/findings/scripts/${script}\` (source repository)`,
    );
  }
  // Whatever `packages/` or `docs/` path remains must be explicitly marked as a repository path.
  for (const line of out.split("\n")) {
    if (/(^|[^/\w])(packages|docs)\//.test(line) && !/source repository/.test(line)) {
      throw new Error(`shipped NOTICE.md still names a repository-only path: ${line}`);
    }
  }
  return out;
}
