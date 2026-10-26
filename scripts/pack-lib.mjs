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
    join(nodeDir, "..", "lib", "node_modules", "npm", "bin", "npm-cli.js"),
  ];
  const cli = candidates.find((candidate) => existsSync(candidate));
  if (cli === undefined) {
    throw new Error(`cannot find npm-cli.js (looked in ${candidates.join(", ")})`);
  }
  return { file: process.execPath, prefixArgs: [cli] };
}

/** Package name of a bare import specifier: `a/b` is `a`, `@s/a/b` is `@s/a`. */
export function packageNameOf(specifier) {
  const parts = specifier.split("/");
  return specifier.startsWith("@") ? parts.slice(0, 2).join("/") : (parts[0] ?? specifier);
}

/**
 * Checks an esbuild metafile: every external import of every output file (static, dynamic and
 * `require`) must be a `node:` built-in or a package listed in `dependencies`. Returns one
 * message per violation; empty means the bundle only needs what the package declares.
 * (A dynamic import whose specifier is not a string literal is invisible here; the build fails
 * on any esbuild warning instead.)
 */
export function findExternalViolations(metafile, dependencies) {
  const allowed = new Set(Object.keys(dependencies));
  const violations = [];
  for (const [output, info] of Object.entries(metafile.outputs)) {
    for (const entry of info.imports) {
      if (!entry.external) continue;
      const specifier = entry.path;
      if (specifier.startsWith("node:")) continue;
      if (builtinModules.includes(specifier)) {
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
