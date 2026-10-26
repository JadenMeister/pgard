import { MAX_ENTRIES_PER_LOCKFILE } from "../limits.js";
import type { ParsedLockfile } from "../types.js";

type Json = Record<string, unknown>;

function isObject(value: unknown): value is Json {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function depNames(value: unknown): string[] {
  return isObject(value) ? Object.keys(value) : [];
}

function manifestDeps(entry: Json): Set<string> {
  return new Set([
    ...depNames(entry["dependencies"]),
    ...depNames(entry["devDependencies"]),
    ...depNames(entry["optionalDependencies"]),
    ...depNames(entry["peerDependencies"]),
  ]);
}

const NODE_MODULES = "node_modules/";

/** `node_modules/a/node_modules/@s/b` -> `@s/b`; `null` when the key is not an installed package. */
function nameFromKey(key: string): string | null {
  const index = key.lastIndexOf(NODE_MODULES);
  if (index === -1) return null;
  if (index !== 0 && key[index - 1] !== "/") return null;
  const name = key.slice(index + NODE_MODULES.length);
  return name === "" ? null : name;
}

/**
 * npm `package-lock.json` / `npm-shrinkwrap.json`. v2/v3 read the flat `packages` map; v1 reads
 * the nested `dependencies` tree (direct/transitive is not recorded there). Nothing is executed
 * and nothing is fetched; the text is only parsed as JSON.
 */
export function parseNpmLock(text: string): ParsedLockfile {
  let root: unknown;
  try {
    root = JSON.parse(text);
  } catch {
    return {
      dependencies: [],
      notes: ["package-lock.json is not valid JSON; no dependencies were read from it."],
      isComplete: false,
    };
  }
  if (!isObject(root)) {
    return {
      dependencies: [],
      notes: ["package-lock.json is not a JSON object; no dependencies were read from it."],
      isComplete: false,
    };
  }
  const notes: string[] = [];
  const found = new Map<string, { name: string; version: string; direct: boolean | undefined }>();
  let isComplete = true;
  let isTruncated = false;
  const add = (name: string, version: string, direct: boolean | undefined): void => {
    const id = `${name}\0${version}`;
    const existing = found.get(id);
    if (existing !== undefined) {
      if (direct === true) existing.direct = true;
      else if (existing.direct === undefined) existing.direct = direct;
      return;
    }
    if (found.size >= MAX_ENTRIES_PER_LOCKFILE) {
      isTruncated = true;
      return;
    }
    found.set(id, { name, version, direct });
  };

  const lockfileVersion = root["lockfileVersion"];
  const packages = root["packages"];
  if (isObject(packages)) {
    // Direct dependency names: the root project and each workspace member's own manifest entry.
    const directByScope = new Map<string, Set<string>>();
    for (const [key, value] of Object.entries(packages)) {
      if (isObject(value) && nameFromKey(key) === null) directByScope.set(key, manifestDeps(value));
    }
    const allDeclared = new Set([...directByScope.values()].flatMap((names) => [...names]));
    let skippedLinks = 0;
    let skippedNoVersion = 0;
    for (const [key, value] of Object.entries(packages)) {
      if (!isObject(value)) continue;
      const installedName = nameFromKey(key);
      if (installedName === null) continue; // the root project and workspace members themselves
      if (value["link"] === true) {
        skippedLinks += 1;
        continue;
      }
      const version = value["version"];
      if (typeof version !== "string" || version === "") {
        skippedNoVersion += 1;
        continue;
      }
      // `npm:real@1.0.0` aliases are installed under the alias; the real name is in `name`.
      const name =
        typeof value["name"] === "string" && value["name"] !== "" ? value["name"] : installedName;
      const nodeModulesAt = key.indexOf(NODE_MODULES);
      const scopeKey = nodeModulesAt <= 0 ? "" : key.slice(0, nodeModulesAt - 1);
      const isTopLevelOfScope =
        key === `${scopeKey === "" ? "" : `${scopeKey}/`}${NODE_MODULES}${installedName}`;
      // Hoisted workspace dependencies live in the root node_modules, so the root counts every
      // workspace member's declared names.
      const declared = scopeKey === "" ? allDeclared : directByScope.get(scopeKey);
      const direct = isTopLevelOfScope && (declared?.has(installedName) ?? false);
      add(name, version, direct);
    }
    if (skippedLinks > 0) {
      notes.push(`${skippedLinks} linked workspace package(s) are first-party and were skipped.`);
    }
    if (skippedNoVersion > 0) {
      isComplete = false;
      notes.push(
        `${skippedNoVersion} package entr${skippedNoVersion === 1 ? "y" : "ies"} had no version and ${skippedNoVersion === 1 ? "was" : "were"} skipped.`,
      );
    }
    if (typeof lockfileVersion !== "number")
      notes.push("lockfileVersion is missing; read as the v2/v3 layout.");
  } else if (isObject(root["dependencies"])) {
    notes.push(
      "package-lock.json is the old v1 format: direct and transitive dependencies are not distinguished.",
    );
    let nonRegistry = 0;
    const walk = (tree: Json, depth: number): void => {
      if (depth > 100) {
        isComplete = false;
        return;
      }
      for (const [name, value] of Object.entries(tree)) {
        if (!isObject(value)) continue;
        const version = value["version"];
        if (typeof version === "string" && /^\d/.test(version)) {
          add(name, version, undefined);
        } else {
          nonRegistry += 1; // file:, link:, git+..., github:, tarball URLs or missing
        }
        if (isObject(value["dependencies"])) walk(value["dependencies"], depth + 1);
      }
    };
    walk(root["dependencies"], 0);
    if (nonRegistry > 0) {
      notes.push(
        `${nonRegistry} dependenc${nonRegistry === 1 ? "y" : "ies"} from file:, link:, git, github or tarball sources have no registry version and ${nonRegistry === 1 ? "was" : "were"} not listed.`,
      );
    }
  } else {
    return {
      dependencies: [],
      notes: [
        "package-lock.json has neither a `packages` nor a `dependencies` section (a project without dependencies, or an unsupported layout).",
      ],
      // A real (even empty) lockfile names its version; anything else is an unknown layout.
      isComplete: typeof lockfileVersion === "number",
    };
  }
  if (isTruncated) {
    isComplete = false;
    notes.push(`Only the first ${MAX_ENTRIES_PER_LOCKFILE} packages were read.`);
  }
  return {
    dependencies: [...found.values()].map(({ name, version, direct }) => ({
      ecosystem: "npm" as const,
      name,
      version,
      ...(direct === undefined ? {} : { direct }),
    })),
    notes,
    isComplete,
  };
}
