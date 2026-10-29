import { MAX_ENTRIES_PER_LOCKFILE } from "../limits.js";
import type { ParsedLockfile } from "../types.js";

function unquote(text: string): string {
  const trimmed = text.trim();
  if (trimmed.length >= 2 && trimmed.startsWith('"') && trimmed.endsWith('"')) {
    try {
      const value: unknown = JSON.parse(trimmed);
      if (typeof value === "string") return value;
    } catch {
      // fall through: keep the text without its quotes
    }
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

/** `@scope/name@^1.0.0` -> `@scope/name`; `null` when there is no `@range` part. */
function nameOfDescriptor(descriptor: string): string | null {
  const at = descriptor.indexOf("@", 1);
  return at <= 0 ? null : descriptor.slice(0, at);
}

interface Block {
  header: string;
  fields: Map<string, string>;
}

/** Splits a yarn.lock into top-level blocks and their direct `key value` / `key: value` lines. */
function readBlocks(text: string): { blocks: Block[]; isCut: boolean } {
  const blocks: Block[] = [];
  let current: Block | null = null;
  let isCut = false;
  for (const rawLine of text.split(/\r?\n/)) {
    if (rawLine.trim() === "" || rawLine.trimStart().startsWith("#")) continue;
    if (!rawLine.startsWith(" ")) {
      if (!rawLine.endsWith(":")) {
        current = null;
        continue;
      }
      if (blocks.length > MAX_ENTRIES_PER_LOCKFILE) {
        isCut = true; // stop building objects; the file is reported as partly read
        break;
      }
      current = { header: rawLine.slice(0, -1), fields: new Map() };
      blocks.push(current);
      continue;
    }
    if (current === null) continue;
    // Only two-space fields belong to the block itself; deeper lines are dependency lists.
    const match = /^ {2}([A-Za-z][\w-]*):? (.*)$/.exec(rawLine);
    if (match === null) continue;
    const key = match[1] as string;
    if (!current.fields.has(key)) current.fields.set(key, (match[2] as string).trim());
  }
  return { blocks, isCut };
}

/**
 * yarn.lock, classic (v1) or berry (v2+). Berry is recognised by its `__metadata` block. Only
 * registry packages (`npm:`) are listed for berry; workspace, patch, git and file entries are
 * counted in the notes. `directNames` (from the sibling package.json files) marks direct ones.
 */
export function parseYarnLock(text: string, directNames?: ReadonlySet<string>): ParsedLockfile {
  const { blocks, isCut: isBlocksCut } = readBlocks(text);
  const isBerry = blocks.some((block) => block.header === "__metadata");
  const notes: string[] = [];
  const seen = new Map<string, { name: string; version: string }>();
  let skipped = 0;
  let isTruncated = isBlocksCut;
  let sawPackage = false;

  for (const block of blocks) {
    if (block.header === "__metadata") continue;
    sawPackage = true;
    const version = block.fields.get("version");
    let name: string | null = null;
    let versionValue: string | undefined = version === undefined ? undefined : unquote(version);
    if (isBerry) {
      const resolution = block.fields.get("resolution");
      const resolved = resolution === undefined ? null : unquote(resolution);
      const npmAt = resolved === null ? -1 : resolved.indexOf("@npm:", 1);
      if (resolved === null || npmAt === -1) {
        skipped += 1; // workspace:, patch:, git, file, portal, link
        continue;
      }
      name = resolved.slice(0, npmAt);
      // `real@npm:1.0.0` aliases appear as `alias@npm:real@npm:1.0.0` in resolution.
      const rest = resolved.slice(npmAt + "@npm:".length);
      const innerAt = rest.indexOf("@npm:", 1);
      if (innerAt !== -1) {
        name = rest.slice(0, innerAt);
        versionValue = rest.slice(innerAt + "@npm:".length);
      } else {
        versionValue ??= rest;
      }
    } else {
      const first = block.header.split(",")[0];
      name = first === undefined ? null : nameOfDescriptor(unquote(first));
    }
    if (name === null || name === "" || versionValue === undefined || versionValue === "") {
      skipped += 1;
      continue;
    }
    const id = `${name}\0${versionValue}`;
    if (seen.has(id)) continue;
    if (seen.size >= MAX_ENTRIES_PER_LOCKFILE) {
      isTruncated = true;
      break;
    }
    seen.set(id, { name, version: versionValue });
  }

  let isComplete = true;
  if (seen.size === 0 && sawPackage) {
    isComplete = false;
    notes.push("yarn.lock has entries but none could be read; the format may be unsupported.");
  } else if (
    seen.size === 0 &&
    !isBerry &&
    text.trim() !== "" &&
    !/^# yarn lockfile v1/m.test(text)
  ) {
    isComplete = false;
    notes.push("yarn.lock was not recognised as yarn v1 or berry; nothing was read.");
  }
  if (skipped > 0) {
    notes.push(
      isBerry
        ? `${skipped} non-registry entr${skipped === 1 ? "y" : "ies"} (workspace, patch, git, file) ${skipped === 1 ? "was" : "were"} not listed.`
        : `${skipped} entr${skipped === 1 ? "y" : "ies"} without a readable name or version ${skipped === 1 ? "was" : "were"} skipped.`,
    );
    if (!isBerry) isComplete = false;
  }
  if (isTruncated) {
    isComplete = false;
    notes.push(`Only the first ${MAX_ENTRIES_PER_LOCKFILE} packages were read.`);
  }
  return {
    dependencies: [...seen.values()].map(({ name, version }) => ({
      ecosystem: "npm" as const,
      name,
      version,
      ...(directNames === undefined ? {} : { direct: directNames.has(name) }),
    })),
    notes,
    isComplete,
  };
}
