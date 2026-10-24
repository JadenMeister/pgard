import type { Ecosystem } from "./osv-db.js";

export interface ResolvedPackage {
  ecosystem: Ecosystem;
  name: string;
  version: string;
}

export interface LockfileParseResult {
  packages: ResolvedPackage[];
  /** Set when the file could not be understood; packages are then incomplete. */
  error: string | null;
  /** Entries that cannot be compared with advisories (git/file/link/workspace, local replaces). */
  uncomparable?: number;
}

/** Version specifiers that do not name a registry release. */
const NON_REGISTRY = /^(git\+|git:|github:|gitlab:|bitbucket:|file:|link:|workspace:|https?:)/;
/**
 * `resolved` values that point away from a registry. Registry tarball URLs (https://...) are the
 * normal npm >= 7 format and stay comparable; only git/file/link sources are excluded.
 */
const NON_REGISTRY_RESOLVED = /^(git\+|git:|github:|gitlab:|bitbucket:|file:|link:)/;

function unique(packages: ResolvedPackage[]): ResolvedPackage[] {
  const seen = new Set<string>();
  return packages.filter((pkg) => {
    const key = `${pkg.ecosystem}\0${pkg.name}\0${pkg.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Splits `name@version` where the name may be scoped (`@scope/name@1.0.0`). */
function splitNameVersion(spec: string): { name: string; version: string } | null {
  const at = spec.lastIndexOf("@");
  if (at <= 0) return null;
  return { name: spec.slice(0, at), version: spec.slice(at + 1) };
}

/** package-lock.json / npm-shrinkwrap.json, lockfileVersion 1, 2 and 3. */
export function parsePackageLock(text: string): LockfileParseResult {
  let data: Record<string, unknown>;
  try {
    data = JSON.parse(text) as Record<string, unknown>;
  } catch {
    return { packages: [], error: "package-lock.json is not valid JSON" };
  }
  const packages: ResolvedPackage[] = [];
  let uncomparable = 0;
  const entries = data.packages;
  if (entries && typeof entries === "object") {
    for (const [key, value] of Object.entries(entries as Record<string, unknown>)) {
      if (!key.includes("node_modules/") || typeof value !== "object" || value === null) continue;
      const entry = value as Record<string, unknown>;
      if (entry.link === true) continue;
      const resolved = typeof entry.resolved === "string" ? entry.resolved : "";
      if (
        typeof entry.version !== "string" ||
        NON_REGISTRY.test(entry.version) ||
        NON_REGISTRY_RESOLVED.test(resolved)
      ) {
        uncomparable += 1;
        continue;
      }
      const name =
        typeof entry.name === "string"
          ? entry.name
          : key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
      packages.push({ ecosystem: "npm", name, version: entry.version });
    }
    return { packages: unique(packages), error: null, uncomparable };
  }
  const walk = (dependencies: unknown) => {
    if (!dependencies || typeof dependencies !== "object") return;
    for (const [name, value] of Object.entries(dependencies as Record<string, unknown>)) {
      if (typeof value !== "object" || value === null) continue;
      const entry = value as Record<string, unknown>;
      const version = typeof entry.version === "string" ? entry.version : "";
      const alias = /^npm:(.+)@([^@]+)$/.exec(version);
      if (alias?.[1] && alias[2]) {
        packages.push({ ecosystem: "npm", name: alias[1], version: alias[2] });
      } else if (version && !NON_REGISTRY.test(version)) {
        packages.push({ ecosystem: "npm", name, version });
      } else {
        uncomparable += 1;
      }
      walk(entry.dependencies);
    }
  };
  if (data.dependencies) {
    walk(data.dependencies);
    return { packages: unique(packages), error: null, uncomparable };
  }
  return { packages: [], error: "package-lock.json has neither packages nor dependencies" };
}

/** pnpm-lock.yaml (v5 `/name/1.0.0`, v6 `/name@1.0.0`, v9 `name@1.0.0`), read line by line. */
export function parsePnpmLock(text: string): LockfileParseResult {
  const packages: ResolvedPackage[] = [];
  let uncomparable = 0;
  let inPackages = false;
  let sawPackagesSection = false;
  for (const line of text.split(/\r?\n/)) {
    if (/^\S/.test(line)) {
      inPackages = /^packages:\s*$/.test(line);
      sawPackagesSection ||= inPackages;
      continue;
    }
    if (!inPackages) continue;
    const match = /^ {2}(['"]?)([^'"\s][^'"]*?)\1:\s*$/.exec(line);
    if (!match?.[2]) continue;
    const key = match[2].replace(/^\//, "").replace(/\(.*$/, "");
    // v5: name/version or @scope/name/version, optionally with a _peer suffix.
    const v5 = /^((?:@[^/@]+\/)?[^/@]+)\/(\d[^/_]*)/.exec(key);
    const parsed = v5?.[1] && v5[2] ? { name: v5[1], version: v5[2] } : splitNameVersion(key);
    if (parsed && /^\d/.test(parsed.version)) {
      packages.push({
        ecosystem: "npm",
        name: parsed.name,
        version: parsed.version.replace(/_.*$/, ""),
      });
    } else {
      // Tarball, git and file: entries (and keys that cannot be read) have no registry version.
      uncomparable += 1;
    }
  }
  if (!sawPackagesSection && text.trim().length > 0 && !/^lockfileVersion:/m.test(text)) {
    return { packages: [], error: "pnpm-lock.yaml was not recognized", uncomparable: 0 };
  }
  return { packages: unique(packages), error: null, uncomparable };
}

/**
 * yarn.lock v1 (`version "1.0.0"`) and Berry (`version: 1.0.0`). Aliases
 * (`alias@npm:real@^1`) resolve to the real package; git/file/link/workspace/patch entries are
 * counted as not comparable.
 */
export function parseYarnLock(text: string): LockfileParseResult {
  const packages: ResolvedPackage[] = [];
  let uncomparable = 0;
  let currentName: string | null = null;
  let sawHeader = /^# yarn lockfile|^__metadata:/m.test(text);
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith("#") || line.trim() === "") continue;
    if (/^\S.*:\s*$/.test(line)) {
      sawHeader = true;
      const firstSpec = line.replace(/:\s*$/, "").split(",")[0]?.trim().replace(/^"|"$/g, "") ?? "";
      currentName = null;
      if (firstSpec.startsWith("__metadata")) continue;
      if (/@(workspace|patch|link|portal|file|git|github|exec):|#|\.git\b/.test(firstSpec)) {
        uncomparable += 1;
        continue;
      }
      const npmIndex = firstSpec.indexOf("@npm:");
      if (npmIndex > 0) {
        const target = firstSpec.slice(npmIndex + "@npm:".length);
        const targetSplit = splitNameVersion(target);
        currentName =
          targetSplit && !/^[\^~<>=*\d]/.test(targetSplit.name)
            ? targetSplit.name
            : firstSpec.slice(0, npmIndex);
      } else {
        currentName = splitNameVersion(firstSpec)?.name ?? null;
      }
      continue;
    }
    const version = /^ {2}version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (version?.[1] && currentName) {
      packages.push({ ecosystem: "npm", name: currentName, version: version[1] });
      currentName = null;
    }
  }
  if (!sawHeader && text.trim().length > 0) {
    return { packages: [], error: "yarn.lock was not recognized", uncomparable };
  }
  return { packages: unique(packages), error: null, uncomparable };
}

/**
 * go.mod `require` lines (single and block form) with `replace` directives applied. A module
 * replaced by a local directory cannot be compared and is counted as such. Versions keep their
 * `v` prefix.
 */
export function parseGoMod(text: string): LockfileParseResult {
  const required: ResolvedPackage[] = [];
  const replaces: {
    from: string;
    fromVersion: string | null;
    to: string;
    toVersion: string | null;
  }[] = [];
  let block: "require" | "replace" | null = null;
  let hasModuleLine = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (/^module\s+\S+/.test(line)) hasModuleLine = true;
    const opening = /^(require|replace)\s*\($/.exec(line);
    if (opening) {
      block = opening[1] as "require" | "replace";
      continue;
    }
    if (block && line === ")") {
      block = null;
      continue;
    }
    const requireLine =
      block === "require" ? /^(\S+)\s+(v\S+)$/.exec(line) : /^require\s+(\S+)\s+(v\S+)$/.exec(line);
    if (requireLine?.[1] && requireLine[2]) {
      required.push({ ecosystem: "Go", name: requireLine[1], version: requireLine[2] });
      continue;
    }
    const replaceLine = (
      block === "replace"
        ? /^(\S+)(?:\s+(v\S+))?\s+=>\s+(\S+)(?:\s+(v\S+))?$/
        : /^replace\s+(\S+)(?:\s+(v\S+))?\s+=>\s+(\S+)(?:\s+(v\S+))?$/
    ).exec(line);
    if (replaceLine?.[1] && replaceLine[3]) {
      replaces.push({
        from: replaceLine[1],
        fromVersion: replaceLine[2] ?? null,
        to: replaceLine[3],
        toVersion: replaceLine[4] ?? null,
      });
    }
  }
  if (!hasModuleLine && text.trim().length > 0) {
    return { packages: [], error: "go.mod was not recognized (no module line)", uncomparable: 0 };
  }
  let uncomparable = 0;
  const packages: ResolvedPackage[] = [];
  for (const pkg of required) {
    const replacement = replaces.find(
      (entry) =>
        entry.from === pkg.name &&
        (entry.fromVersion === null || entry.fromVersion === pkg.version),
    );
    if (!replacement) {
      packages.push(pkg);
    } else if (/^(\.{1,2}\/|\/)/.test(replacement.to) || replacement.toVersion === null) {
      uncomparable += 1; // replaced by a local directory
    } else {
      packages.push({ ecosystem: "Go", name: replacement.to, version: replacement.toVersion });
    }
  }
  return { packages: unique(packages), error: null, uncomparable };
}

/** go.sum entries (used when no go.mod is present). `/go.mod` hash lines are ignored. */
export function parseGoSum(text: string): LockfileParseResult {
  const packages: ResolvedPackage[] = [];
  for (const line of text.split(/\r?\n/)) {
    const match = /^(\S+)\s+(v[^\s/]+)\s+h1:/.exec(line);
    if (match?.[1] && match[2])
      packages.push({ ecosystem: "Go", name: match[1], version: match[2] });
  }
  // A go.sum holding only `/go.mod` hash lines is still valid.
  const isGoSumFormat = /^\S+\s+v\S+\s+h1:/m.test(text);
  if (packages.length === 0 && text.trim().length > 0 && !isGoSumFormat) {
    return { packages: [], error: "go.sum was not recognized" };
  }
  return { packages: unique(packages), error: null };
}
