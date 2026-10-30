import path from "node:path";
import { readSmallRegularFile } from "@pgard/git-history";
import { sanitizeDisplayText } from "./display-text.js";
import type { ProjectSignals } from "./relatedness.js";

/**
 * Per file; a larger manifest is skipped, never partly read. The files belong to a repository
 * PGARD does not trust, and everything here runs synchronously: no pattern below may backtrack
 * over more than one short line, and a line over `MAX_LINE_LENGTH` is not looked at.
 */
const MAX_MANIFEST_BYTES = 64 * 1024;
const MAX_LINE_LENGTH = 1024;
const MAX_LINES = 5000;
const MAX_DEPENDENCIES = 5000;
const MAX_NAME_LENGTH = 200;

type Reader = (filePath: string, maxBytes: number) => Promise<string | null>;

/** A plain small regular file or `null` (absent, a symlink, special, too large, unreadable). */
const readText: Reader = async (filePath, maxBytes) => {
  const read = await readSmallRegularFile(filePath, maxBytes).catch(() => null);
  return read !== null && read.state === "ok" ? read.text : null;
};

function cleanName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const cleaned = sanitizeDisplayText(value.slice(0, MAX_NAME_LENGTH * 2), MAX_NAME_LENGTH);
  return cleaned === "" ? null : cleaned;
}

/** `@scope/name` and `vendor/name` count as `name`. */
function lastSegment(value: string): string {
  return (
    value
      .split("/")
      .filter((part) => part !== "")
      .pop() ?? value
  );
}

function parseJson(text: string | null): Record<string, unknown> | null {
  if (text === null) return null;
  try {
    const value: unknown = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text);
    return typeof value === "object" && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function keysOf(value: unknown): string[] {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? Object.keys(value as Record<string, unknown>).slice(0, MAX_DEPENDENCIES)
    : [];
}

/** The lines worth looking at: a BOM is dropped, long lines and anything past the cap are not. */
function shortLines(text: string): string[] {
  const lines: string[] = [];
  const body = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
  for (const line of body.split("\n", MAX_LINES)) {
    if (line.length <= MAX_LINE_LENGTH) lines.push(line.endsWith("\r") ? line.slice(0, -1) : line);
  }
  return lines;
}

const normalizePython = (name: string): string => name.toLowerCase().replaceAll("_", "-");

/** Quoted strings of one line, found by scanning (no pattern over the whole line). */
function quotedStrings(line: string): string[] {
  const found: string[] = [];
  let index = 0;
  while (index < line.length) {
    const quote = line[index];
    if (quote !== '"' && quote !== "'") {
      index += 1;
      continue;
    }
    const end = line.indexOf(quote, index + 1);
    if (end < 0) break;
    found.push(line.slice(index + 1, end));
    index = end + 1;
  }
  return found;
}

/** True when `]` appears at or after `from` outside a quoted string. */
function closesArray(line: string, from: number): boolean {
  let quote: string | null = null;
  for (let index = from; index < line.length; index += 1) {
    const char = line[index];
    if (quote !== null) {
      if (char === quote) quote = null;
    } else if (char === '"' || char === "'") {
      quote = char;
    } else if (char === "]") {
      return true;
    }
  }
  return false;
}

const REQUIREMENT_NAME = /^[A-Za-z][A-Za-z0-9._-]*/;
const TOML_TABLE = /^[ \t]*\[+([^\][\n]*)\]+/;
const TOML_KEY = /^[ \t]*([A-Za-z][A-Za-z0-9._-]*)[ \t]*=/;
const TOML_NAME = /^[ \t]*name[ \t]*=[ \t]*["']([^"'\n]*)["']/;
const TOML_DEPENDENCIES_START = /^[ \t]*dependencies[ \t]*=[ \t]*\[/;

/**
 * `pyproject.toml`, line by line: the `name` of `[project]` or `[tool.poetry]`, the strings of
 * `dependencies = [...]` and of `[project.optional-dependencies]`, and the keys of the
 * `[tool.poetry...dependencies]` tables. Descriptions, URLs and other keys are not dependencies.
 */
function readPyproject(text: string): { name: string | null; dependencies: string[] } {
  let table = "";
  let name: string | null = null;
  let isInDependencyArray = false;
  const dependencies: string[] = [];
  const addRequirement = (value: string): void => {
    const match = REQUIREMENT_NAME.exec(value.trim());
    if (match !== null) dependencies.push(normalizePython(match[0]));
  };
  for (const line of shortLines(text)) {
    const header = TOML_TABLE.exec(line);
    if (header !== null && !isInDependencyArray) {
      table = (header[1] ?? "").trim();
      continue;
    }
    if (table === "project" || table === "tool.poetry") {
      if (name === null) name = TOML_NAME.exec(line)?.[1] ?? null;
    }
    if (table === "project" && (isInDependencyArray || TOML_DEPENDENCIES_START.test(line))) {
      for (const value of quotedStrings(line)) addRequirement(value);
      // The array ends at the first line holding `]` after the opening one.
      const opening: number = isInDependencyArray ? 0 : line.indexOf("[") + 1;
      isInDependencyArray = !closesArray(line, opening);
    } else if (table === "project.optional-dependencies") {
      for (const value of quotedStrings(line)) addRequirement(value);
    } else if (/^tool\.poetry(\.group\.[^.]+)?\.(dev-)?dependencies$/.test(table)) {
      const key = TOML_KEY.exec(line)?.[1];
      if (key !== undefined) dependencies.push(normalizePython(key));
    }
  }
  return { name, dependencies };
}

function requirementNames(text: string): string[] {
  const names: string[] = [];
  for (const line of shortLines(text)) {
    const match = REQUIREMENT_NAME.exec(line.trimStart());
    if (match !== null) names.push(normalizePython(match[0]));
  }
  return names;
}

const GO_MODULE = /^[ \t]*module[ \t]+(\S+)/;
const GO_REQUIRE = /^[ \t]*(?:require[ \t]+)?([a-z0-9][a-z0-9.-]*\/\S+)[ \t]+v/;

function readGoMod(text: string): { module: string | null; requires: string[] } {
  let module: string | null = null;
  const requires: string[] = [];
  for (const line of shortLines(text)) {
    if (module === null) module = GO_MODULE.exec(line)?.[1] ?? null;
    const required = GO_REQUIRE.exec(line)?.[1];
    if (required !== undefined) requires.push(required.toLowerCase());
  }
  return { module, requires };
}

const GEM_RAILS = /^[ \t]*gem[ \t]+["']rails["']/;

/**
 * Reads, locally and read-only, what names the project at `root` and which frameworks it
 * declares. Only a few well-known manifests at the top of the folder are read, each through the
 * safe small-file reader (no symlinks, no special files, 64 KB cap). Nothing is executed and
 * nothing outside `root` is touched. Never throws: whatever cannot be read is simply missing.
 */
export async function readProjectSignals(
  root: string,
  repo: string | null,
  read: Reader = readText,
): Promise<ProjectSignals> {
  const file = (name: string): Promise<string | null> =>
    read(path.join(root, name), MAX_MANIFEST_BYTES).catch(() => null);
  const [packageJson, pyproject, requirements, composer, goMod, pom, gradle, gradleKts, gemfile] =
    await Promise.all([
      file("package.json"),
      file("pyproject.toml"),
      file("requirements.txt"),
      file("composer.json"),
      file("go.mod"),
      file("pom.xml"),
      file("build.gradle"),
      file("build.gradle.kts"),
      file("Gemfile"),
    ]);

  const names: string[] = [];
  const dependencies: string[] = [];

  const pkg = parseJson(packageJson);
  if (pkg !== null) {
    const name = cleanName(pkg["name"]);
    if (name !== null) names.push(lastSegment(name));
    for (const field of ["dependencies", "devDependencies", "peerDependencies"]) {
      dependencies.push(...keysOf(pkg[field]).map((key) => key.toLowerCase()));
    }
  }
  if (pyproject !== null) {
    const parsed = readPyproject(pyproject);
    const name = cleanName(parsed.name);
    if (name !== null) names.push(name);
    dependencies.push(...parsed.dependencies);
  }
  if (requirements !== null) dependencies.push(...requirementNames(requirements));
  const composerJson = parseJson(composer);
  if (composerJson !== null) {
    const name = cleanName(composerJson["name"]);
    if (name !== null) names.push(lastSegment(name));
    for (const field of ["require", "require-dev"]) {
      dependencies.push(...keysOf(composerJson[field]).map((key) => key.toLowerCase()));
    }
  }
  if (goMod !== null) {
    const parsed = readGoMod(goMod);
    const name = cleanName(parsed.module);
    if (name !== null) names.push(lastSegment(name));
    dependencies.push(...parsed.requires);
  }
  for (const build of [pom, gradle, gradleKts]) {
    if (
      build !== null &&
      (build.includes("spring-boot") || build.includes("org.springframework.boot"))
    ) {
      dependencies.push("org.springframework.boot");
    }
  }
  if (gemfile !== null && shortLines(gemfile).some((line) => GEM_RAILS.test(line))) {
    dependencies.push("rails");
  }

  const folder = cleanName(path.basename(root));
  return {
    folderName: folder,
    repo: repo === null ? null : cleanName(repo),
    manifestNames: [...new Set(names)],
    dependencies: [...new Set(dependencies)].slice(0, MAX_DEPENDENCIES),
  };
}
