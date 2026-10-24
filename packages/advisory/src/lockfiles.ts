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
}

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
  const entries = data.packages;
  if (entries && typeof entries === "object") {
    for (const [key, value] of Object.entries(entries as Record<string, unknown>)) {
      if (!key.includes("node_modules/") || typeof value !== "object" || value === null) continue;
      const entry = value as Record<string, unknown>;
      if (entry.link === true || typeof entry.version !== "string") continue;
      const name =
        typeof entry.name === "string"
          ? entry.name
          : key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
      packages.push({ ecosystem: "npm", name, version: entry.version });
    }
    return { packages: unique(packages), error: null };
  }
  const walk = (dependencies: unknown) => {
    if (!dependencies || typeof dependencies !== "object") return;
    for (const [name, value] of Object.entries(dependencies as Record<string, unknown>)) {
      if (typeof value !== "object" || value === null) continue;
      const entry = value as Record<string, unknown>;
      if (typeof entry.version === "string" && !entry.version.startsWith("file:")) {
        packages.push({ ecosystem: "npm", name, version: entry.version });
      }
      walk(entry.dependencies);
    }
  };
  if (data.dependencies) {
    walk(data.dependencies);
    return { packages: unique(packages), error: null };
  }
  return { packages: [], error: "package-lock.json has neither packages nor dependencies" };
}

/** pnpm-lock.yaml (v5 `/name/1.0.0`, v6 `/name@1.0.0`, v9 `name@1.0.0`), read line by line. */
export function parsePnpmLock(text: string): LockfileParseResult {
  const packages: ResolvedPackage[] = [];
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
    }
  }
  if (!sawPackagesSection && text.trim().length > 0 && !/^lockfileVersion:/m.test(text)) {
    return { packages: [], error: "pnpm-lock.yaml was not recognized" };
  }
  return { packages: unique(packages), error: null };
}

/** yarn.lock v1 (`version "1.0.0"`) and Berry (`version: 1.0.0`, `name@npm:range`). */
export function parseYarnLock(text: string): LockfileParseResult {
  const packages: ResolvedPackage[] = [];
  let currentName: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (line.startsWith("#") || line.trim() === "") continue;
    if (/^\S.*:\s*$/.test(line)) {
      const firstSpec = line.replace(/:\s*$/, "").split(",")[0]?.trim().replace(/^"|"$/g, "") ?? "";
      const spec = firstSpec.replace(/@npm:/, "@");
      const parsed = splitNameVersion(spec);
      currentName = firstSpec.startsWith("__metadata") ? null : (parsed?.name ?? null);
      if (currentName && /@(workspace|patch|link|portal|file):/.test(firstSpec)) currentName = null;
      continue;
    }
    const version = /^ {2}version:?\s+"?([^"\s]+)"?\s*$/.exec(line);
    if (version?.[1] && currentName) {
      packages.push({ ecosystem: "npm", name: currentName, version: version[1] });
      currentName = null;
    }
  }
  return { packages: unique(packages), error: null };
}

/** go.mod `require` lines (single and block form). Versions keep their `v` prefix. */
export function parseGoMod(text: string): LockfileParseResult {
  const packages: ResolvedPackage[] = [];
  let inRequire = false;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\/\/.*$/, "").trim();
    if (/^require\s*\($/.test(line)) {
      inRequire = true;
      continue;
    }
    if (inRequire && line === ")") {
      inRequire = false;
      continue;
    }
    const match = (inRequire ? /^(\S+)\s+(v\S+)$/ : /^require\s+(\S+)\s+(v\S+)$/).exec(line);
    if (match?.[1] && match[2])
      packages.push({ ecosystem: "Go", name: match[1], version: match[2] });
  }
  return { packages: unique(packages), error: null };
}

/** go.sum entries (used when no go.mod is present). `/go.mod` hash lines are ignored. */
export function parseGoSum(text: string): LockfileParseResult {
  const packages: ResolvedPackage[] = [];
  for (const line of text.split(/\r?\n/)) {
    const match = /^(\S+)\s+(v[^\s/]+)\s+h1:/.exec(line);
    if (match?.[1] && match[2])
      packages.push({ ecosystem: "Go", name: match[1], version: match[2] });
  }
  return { packages: unique(packages), error: null };
}
