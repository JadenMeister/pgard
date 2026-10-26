import { MAX_ENTRIES_PER_LOCKFILE } from "../limits.js";
import type { ParsedLockfile } from "../types.js";

interface GoModule {
  name: string;
  version: string;
  direct: boolean;
}

const VERSION = /^v\d+\.\d+\.\d+[^\s]*$/;

/** Removes a `//` comment (returns the comment separately for the `// indirect` marker). */
function splitComment(line: string): { code: string; comment: string } {
  const at = line.indexOf("//");
  return at === -1
    ? { code: line.trim(), comment: "" }
    : { code: line.slice(0, at).trim(), comment: line.slice(at + 2).trim() };
}

function unquoteGo(token: string): string {
  if (token.length >= 2 && (token.startsWith('"') || token.startsWith("`"))) {
    return token.slice(1, -1);
  }
  return token;
}

/** Compares `v1.2.3`-style versions loosely (numeric core, then string) to find the highest. */
function compareGoVersions(a: string, b: string): number {
  const core = (version: string): number[] =>
    version
      .replace(/^v/, "")
      .split(/[-+]/)[0]!
      .split(".")
      .map((part) => Number.parseInt(part, 10) || 0);
  const left = core(a);
  const right = core(b);
  for (let index = 0; index < 3; index += 1) {
    const difference = (left[index] ?? 0) - (right[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return a < b ? -1 : a > b ? 1 : 0;
}

interface Directive {
  verb: string;
  rest: string;
  comment: string;
}

function directives(text: string): Directive[] {
  const result: Directive[] = [];
  let block: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    const { code, comment } = splitComment(line);
    if (code === "") continue;
    if (block !== null) {
      if (code === ")") block = null;
      else result.push({ verb: block, rest: code, comment });
      continue;
    }
    const blockStart = /^(\w+)\s*\($/.exec(code);
    if (blockStart !== null) {
      block = blockStart[1] as string;
      continue;
    }
    const space = code.search(/\s/);
    result.push({
      verb: space === -1 ? code : code.slice(0, space),
      rest: space === -1 ? "" : code.slice(space).trim(),
      comment,
    });
  }
  return result;
}

/**
 * `go.mod`: the `require` list is the resolved module set of the build (minimal version
 * selection); `// indirect` marks transitive ones. `replace` directives that point at another
 * module version are applied; replacements by a local path are first-party code and are noted.
 * `go.sum` is consulted only to add transitive modules that a pre-1.17 go.mod does not list.
 */
export function parseGoMod(text: string, goSum?: string): ParsedLockfile {
  const notes: string[] = [];
  const requires = new Map<string, GoModule>();
  const replacements = new Map<
    string,
    { to: string; version: string | null; from: string | null }
  >();
  let goVersion: string | null = null;
  let isComplete = true;
  let sawModule = false;
  for (const directive of directives(text)) {
    if (directive.verb === "module") sawModule = true;
    else if (directive.verb === "go") goVersion = directive.rest.split(/\s+/)[0] ?? null;
    else if (directive.verb === "require") {
      const [rawName = "", version = ""] = directive.rest.split(/\s+/);
      const name = unquoteGo(rawName);
      if (name === "" || !VERSION.test(version)) {
        isComplete = false;
        continue;
      }
      if (requires.size >= MAX_ENTRIES_PER_LOCKFILE) {
        isComplete = false;
        break;
      }
      requires.set(`${name}@${version}`, {
        name,
        version,
        direct: !/^indirect\b/.test(directive.comment),
      });
    } else if (directive.verb === "replace") {
      const [left, right] = directive.rest.split("=>").map((part) => part.trim());
      if (left === undefined || right === undefined) continue;
      const [fromName = "", fromVersion] = left.split(/\s+/);
      const [toName = "", toVersion] = right.split(/\s+/);
      replacements.set(unquoteGo(fromName), {
        to: unquoteGo(toName),
        version: toVersion ?? null,
        from: fromVersion ?? null,
      });
    }
  }
  if (!sawModule) {
    isComplete = false;
    notes.push("go.mod has no `module` line; it may not be a Go module file.");
  }

  const modules: GoModule[] = [];
  let localReplacements = 0;
  for (const required of requires.values()) {
    const replacement = replacements.get(required.name);
    if (
      replacement === undefined ||
      (replacement.from !== null && replacement.from !== required.version)
    ) {
      modules.push(required);
    } else if (replacement.version !== null && VERSION.test(replacement.version)) {
      modules.push({ name: replacement.to, version: replacement.version, direct: required.direct });
    } else {
      localReplacements += 1; // replaced by a local directory: first-party code
    }
  }
  if (localReplacements > 0) {
    notes.push(
      `${localReplacements} module(s) are replaced by a local path in go.mod and were not listed.`,
    );
  }

  const [goMajor = 0, goMinor = 0] = (goVersion ?? "")
    .split(".")
    .map((part) => Number.parseInt(part, 10));
  const listsIndirect = goMajor > 1 || (goMajor === 1 && goMinor >= 17);
  if (!listsIndirect && goSum !== undefined) {
    const known = new Set(modules.map((module) => module.name));
    const best = new Map<string, string>();
    for (const module of parseGoSumModules(goSum)) {
      if (known.has(module.name)) continue;
      const current = best.get(module.name);
      if (current === undefined || compareGoVersions(module.version, current) > 0) {
        best.set(module.name, module.version);
      }
    }
    for (const [name, version] of best) modules.push({ name, version, direct: false });
    if (best.size > 0) {
      notes.push(
        `go.mod declares go ${goVersion ?? "(unknown)"} (before 1.17) and lists no transitive modules; ${best.size} were added from go.sum at their highest recorded version, which can include versions the build does not use.`,
      );
    }
  } else if (!listsIndirect && goSum === undefined && requires.size > 0) {
    notes.push(
      `go.mod declares go ${goVersion ?? "(unknown)"} (before 1.17) and lists no transitive modules, and there is no go.sum; transitive modules are not covered.`,
    );
    isComplete = false;
  }
  return {
    dependencies: modules.map((module) => ({
      ecosystem: "Go" as const,
      name: module.name,
      version: module.version,
      direct: module.direct,
    })),
    notes,
    isComplete,
  };
}

function parseGoSumModules(text: string): { name: string; version: string }[] {
  const modules: { name: string; version: string }[] = [];
  for (const line of text.split(/\r?\n/)) {
    const [name, version, hash] = line.trim().split(/\s+/);
    if (name === undefined || version === undefined || hash === undefined) continue;
    if (version.endsWith("/go.mod") || !VERSION.test(version)) continue;
    modules.push({ name, version });
    if (modules.length >= MAX_ENTRIES_PER_LOCKFILE) break;
  }
  return modules;
}

/** `go.sum` alone (no go.mod next to it): every recorded module version, direct-ness unknown. */
export function parseGoSum(text: string): ParsedLockfile {
  const modules = parseGoSumModules(text);
  const unique = new Map(modules.map((module) => [`${module.name}@${module.version}`, module]));
  const notes = [
    "No go.mod next to this go.sum: it can include versions the build does not select, and which modules are direct is unknown.",
  ];
  const isComplete = text.trim() === "" || unique.size > 0;
  if (!isComplete) notes.push("go.sum has no lines in the `module version hash` format.");
  return {
    dependencies: [...unique.values()].map((module) => ({
      ecosystem: "Go" as const,
      name: module.name,
      version: module.version,
    })),
    notes,
    isComplete,
  };
}
