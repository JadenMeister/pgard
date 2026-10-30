import path from "node:path";
import { readSmallRegularFile } from "@pgard/git-history";
import { sanitizeDisplayText } from "./display-text.js";
import type { ProjectSignals } from "./relatedness.js";

/** Per file; a manifest larger than this is skipped, never partly read. */
const MAX_MANIFEST_BYTES = 512 * 1024;
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
  const cleaned = sanitizeDisplayText(value, MAX_NAME_LENGTH);
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
    const value: unknown = JSON.parse(text);
    return typeof value === "object" && value !== null && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function keysOf(value: unknown): string[] {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? Object.keys(value as Record<string, unknown>)
    : [];
}

/** The first `name = "..."` inside a TOML table such as `[project]` or `[tool.poetry]`. */
function tomlTableName(text: string, tables: readonly string[]): string | null {
  for (const table of tables) {
    const start = text.indexOf(`[${table}]`);
    if (start < 0) continue;
    const rest = text.slice(start + table.length + 2);
    const end = rest.search(/^\[/m);
    const body = end < 0 ? rest : rest.slice(0, end);
    const match = /^\s*name\s*=\s*["']([^"'\n]+)["']/m.exec(body);
    if (match?.[1] !== undefined) return match[1];
  }
  return null;
}

/** Names from `"flask>=2"` style strings and `django = "^4"` keys; non-names are harmless. */
function pythonDependencyNames(text: string): string[] {
  const names: string[] = [];
  for (const match of text.matchAll(
    /["']\s*([A-Za-z][A-Za-z0-9._-]*)\s*(?:\[[^\]\n]*\])?\s*(?:[<>=!~;@ ][^"'\n]*)?["']/g,
  )) {
    if (match[1] !== undefined) names.push(match[1]);
  }
  for (const match of text.matchAll(/^\s*([A-Za-z][A-Za-z0-9._-]*)\s*=/gm)) {
    if (match[1] !== undefined) names.push(match[1]);
  }
  return names.map((name) => name.toLowerCase().replaceAll("_", "-"));
}

function requirementNames(text: string): string[] {
  const names: string[] = [];
  for (const line of text.split("\n")) {
    const match = /^\s*([A-Za-z][A-Za-z0-9._-]*)/.exec(line);
    if (match?.[1] !== undefined) names.push(match[1].toLowerCase().replaceAll("_", "-"));
  }
  return names;
}

function goModules(text: string): { module: string | null; requires: string[] } {
  const module = /^\s*module\s+(\S+)/m.exec(text)?.[1] ?? null;
  const requires: string[] = [];
  for (const match of text.matchAll(/^\s*(?:require\s+)?([a-z0-9.-]+\.[a-z]+\/\S+)\s+v\S+/gm)) {
    if (match[1] !== undefined) requires.push(match[1].toLowerCase());
  }
  return { module, requires };
}

/**
 * Reads, locally and read-only, what names the project at `root` and which frameworks it
 * declares. Only a few well-known manifests at the top of the folder are read, each through the
 * safe small-file reader (no symlinks, no special files, size capped). Nothing is executed and
 * nothing outside `root` is touched. Never throws: whatever cannot be read is simply missing.
 */
export async function readProjectSignals(
  root: string,
  repo: string | null,
  read: Reader = readText,
): Promise<ProjectSignals> {
  const file = (name: string): Promise<string | null> =>
    read(path.join(root, name), MAX_MANIFEST_BYTES);
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
    ]).catch(() => [null, null, null, null, null, null, null, null, null] as const);

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
    const name = cleanName(tomlTableName(pyproject, ["project", "tool.poetry"]));
    if (name !== null) names.push(name);
    dependencies.push(...pythonDependencyNames(pyproject));
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
    const { module, requires } = goModules(goMod);
    const name = cleanName(module);
    if (name !== null) names.push(lastSegment(name));
    dependencies.push(...requires);
  }
  for (const build of [pom, gradle, gradleKts]) {
    if (build !== null && /spring-boot|org\.springframework\.boot/.test(build)) {
      dependencies.push("org.springframework.boot");
    }
  }
  if (gemfile !== null && /^\s*gem\s+["']rails["']/m.test(gemfile)) dependencies.push("rails");

  const folder = cleanName(path.basename(root));
  return {
    folderName: folder,
    repo: repo === null ? null : cleanName(repo),
    manifestNames: [...new Set(names)],
    dependencies: [...new Set(dependencies)].slice(0, MAX_DEPENDENCIES),
  };
}
