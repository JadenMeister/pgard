import { MAX_ENTRIES_PER_LOCKFILE } from "../limits.js";
import type { ParsedLockfile } from "../types.js";

/**
 * A deliberately small reader for the subset of YAML that pnpm writes: block mappings with
 * scalar or flow (`{...}`) values, no tags, anchors, aliases or merge keys. Anything outside that
 * subset makes the whole file "partial" instead of being guessed at. It never builds objects from
 * the text, so there is no custom-tag or prototype surface.
 */
interface Node {
  key: string;
  value: string;
  indent: number;
  children: Node[];
}

const KEY_PATTERN =
  /^( *)('(?:[^']|'')*'|"(?:[^"\\]|\\.)*"|[^\s'"#\-?!&*|>%@`][^]*?|-[^\s][^]*?):(?:[ \t]+(.*))?$/;

function unquoteKey(raw: string): string {
  if (raw.startsWith("'") && raw.endsWith("'") && raw.length >= 2) {
    return raw.slice(1, -1).replace(/''/g, "'");
  }
  if (raw.startsWith('"') && raw.endsWith('"') && raw.length >= 2) {
    try {
      const value: unknown = JSON.parse(raw);
      if (typeof value === "string") return value;
    } catch {
      // keep the raw text without quotes
    }
    return raw.slice(1, -1);
  }
  return raw;
}

function unquoteValue(raw: string): string {
  const withoutComment = raw.replace(/\s+#.*$/, "").trim();
  return unquoteKey(withoutComment);
}

class UnsupportedYaml extends Error {}

function parseDocument(lines: readonly string[]): Node {
  const root: Node = { key: "", value: "", indent: -1, children: [] };
  const stack: Node[] = [root];
  let blockScalarIndent = -1;
  for (const line of lines) {
    if (line.trim() === "" || line.trimStart().startsWith("#")) continue;
    const lineIndent = line.length - line.trimStart().length;
    if (blockScalarIndent !== -1) {
      if (lineIndent > blockScalarIndent) continue; // body of a `|` / `>` scalar
      blockScalarIndent = -1;
    }
    if (line.includes("\t") && line.slice(0, lineIndent).includes("\t")) {
      throw new UnsupportedYaml("tab indentation");
    }
    const trimmed = line.trimStart();
    if (trimmed.startsWith("- ") || trimmed === "-") continue; // list items carry no package keys
    const match = KEY_PATTERN.exec(line);
    if (match === null) throw new UnsupportedYaml("a line that is not a mapping entry");
    const indent = (match[1] as string).length;
    const rawValue = (match[3] ?? "").trim();
    if (/^(?:[&*]\w|!)/.test(rawValue) || (match[2] as string).startsWith("<<")) {
      throw new UnsupportedYaml("YAML tags, anchors or aliases");
    }
    const node: Node = {
      key: unquoteKey(match[2] as string),
      value: rawValue === "" ? "" : unquoteValue(rawValue),
      indent,
      children: [],
    };
    if (/^[|>]/.test(rawValue)) {
      blockScalarIndent = indent;
      node.value = "";
    }
    while (stack.length > 1 && (stack[stack.length - 1] as Node).indent >= indent) stack.pop();
    (stack[stack.length - 1] as Node).children.push(node);
    stack.push(node);
  }
  return root;
}

function child(node: Node | undefined, key: string): Node | undefined {
  return node?.children.find((candidate) => candidate.key === key);
}

const SEMVERISH = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?$/;

/** Splits a `packages:` key into name and version for every pnpm lockfile generation. */
function splitPackageKey(key: string): { name: string; version: string } | null {
  // v5: /name/1.2.3 or /@scope/name/1.2.3_peer@1
  const v5 = /^\/((?:@[^/]+\/)?[^/@]+)\/(\d[^/_]*)(?:_.*)?$/.exec(key);
  if (v5 !== null) return { name: v5[1] as string, version: v5[2] as string };
  // v6: /name@1.2.3(peer@1)   v9: name@1.2.3(peer@1)
  const stripped = key.replace(/^\//, "").replace(/\(.*$/, "");
  const at = stripped.indexOf("@", 1);
  if (at <= 0) return null;
  const name = stripped.slice(0, at);
  const version = stripped.slice(at + 1).replace(/_.*$/, "");
  return { name, version };
}

/** Importer dependency value -> bare version, or `null` for links and other non-registry specs. */
function importerVersion(value: string): string | null {
  const bare = value.replace(/\(.*$/, "").replace(/_.*$/, "");
  return SEMVERISH.test(bare) ? bare : null;
}

function collectImporterDirects(importer: Node | undefined, directs: Set<string>): void {
  if (importer === undefined) return;
  for (const section of ["dependencies", "devDependencies", "optionalDependencies"]) {
    for (const dep of child(importer, section)?.children ?? []) {
      // v6+/v9: `name:` -> `specifier:` + `version:`. v5: `name: 1.2.3`.
      const version = dep.value !== "" ? dep.value : (child(dep, "version")?.value ?? "");
      const bare = importerVersion(version);
      if (bare !== null) directs.add(`${dep.key}\0${bare}`);
    }
  }
}

export function parsePnpmLock(text: string): ParsedLockfile {
  const notes: string[] = [];
  const documents: string[][] = [[]];
  for (const line of text.split(/\r?\n/)) {
    if (line === "---" || line.startsWith("--- ")) {
      documents.push([]);
      continue;
    }
    (documents[documents.length - 1] as string[]).push(line);
  }
  const found = new Map<string, { name: string; version: string; direct: boolean }>();
  let isComplete = true;
  let isTruncated = false;
  let sawVersion = false;
  let skipped = 0;

  for (const lines of documents) {
    if (lines.every((line) => line.trim() === "" || line.trimStart().startsWith("#"))) continue;
    let root: Node;
    try {
      root = parseDocument(lines);
    } catch (error) {
      isComplete = false;
      notes.push(
        `pnpm-lock.yaml uses ${error instanceof UnsupportedYaml ? error.message : "unsupported syntax"}, which PGARD does not read; that part was skipped.`,
      );
      continue;
    }
    if (child(root, "lockfileVersion") !== undefined) sawVersion = true;
    const directs = new Set<string>();
    const importers = child(root, "importers");
    if (importers !== undefined) {
      for (const importer of importers.children) collectImporterDirects(importer, directs);
    } else {
      collectImporterDirects(root, directs); // v5 single-project layout
    }
    const packages = child(root, "packages");
    for (const entry of packages?.children ?? []) {
      const parts = splitPackageKey(entry.key);
      if (parts === null || !SEMVERISH.test(parts.version)) {
        skipped += 1; // tarball, git or directory dependency
        continue;
      }
      const id = `${parts.name}\0${parts.version}`;
      if (found.has(id)) continue;
      if (found.size >= MAX_ENTRIES_PER_LOCKFILE) {
        isTruncated = true;
        break;
      }
      found.set(id, { ...parts, direct: directs.has(id) });
    }
    // v9 lists resolved packages again under `snapshots:`; versions are the same set, but a
    // package that only appears there still counts.
    for (const entry of child(root, "snapshots")?.children ?? []) {
      const parts = splitPackageKey(entry.key);
      if (parts === null || !SEMVERISH.test(parts.version)) continue;
      const id = `${parts.name}\0${parts.version}`;
      if (!found.has(id) && found.size < MAX_ENTRIES_PER_LOCKFILE) {
        found.set(id, { ...parts, direct: directs.has(id) });
      }
    }
  }

  if (!sawVersion) {
    isComplete = false;
    notes.push("pnpm-lock.yaml has no lockfileVersion; the format was not recognised.");
  }
  if (skipped > 0) {
    notes.push(
      `${skipped} tarball, git or directory dependenc${skipped === 1 ? "y" : "ies"} without a registry version ${skipped === 1 ? "was" : "were"} not listed.`,
    );
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
      direct,
    })),
    notes,
    isComplete,
  };
}
