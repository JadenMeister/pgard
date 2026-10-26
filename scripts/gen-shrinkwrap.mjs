#!/usr/bin/env node
// Regenerates packaging/pgard/npm-shrinkwrap.json: the exact transitive tree of the package's own
// dependencies. It is resolved from a clean temporary directory that holds only
// packaging/pgard/package.json, so none of the monorepo's dev tooling can leak into it, and with
// --ignore-scripts so nothing is executed. Run it after changing the package's dependencies
// (`npm run pack:shrinkwrap`); pack-pgard.mjs fails when the file is out of date. Needs network.
import { spawnSync } from "node:child_process";
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { npmCommand } from "./pack-lib.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const dir = mkdtempSync(join(tmpdir(), "pgard shrinkwrap "));
try {
  copyFileSync(join(root, "packaging/pgard/package.json"), join(dir, "package.json"));
  const npm = npmCommand();
  const result = spawnSync(
    npm.file,
    [
      ...npm.prefixArgs,
      "install",
      "--package-lock-only",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
    ],
    { cwd: dir, encoding: "utf8" },
  );
  if (result.status !== 0) throw new Error(`npm install failed:\n${result.stdout}${result.stderr}`);
  const lock = JSON.parse(readFileSync(join(dir, "package-lock.json"), "utf8"));
  writeFileSync(
    join(root, "packaging/pgard/npm-shrinkwrap.json"),
    `${JSON.stringify(lock, null, 2)}\n`,
  );
  console.log(
    `wrote packaging/pgard/npm-shrinkwrap.json (${Object.keys(lock.packages).length - 1} packages)`,
  );
} finally {
  rmSync(dir, { recursive: true, force: true });
}
