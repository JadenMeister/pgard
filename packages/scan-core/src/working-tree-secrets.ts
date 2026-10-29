import { lstat, open, readdir } from "node:fs/promises";
import path from "node:path";
import {
  compilePathMatcher,
  FINDING_TEXT_VARIANTS,
  type Coverage,
  type Finding,
} from "@pgard/findings";
import { scanStagedSecrets } from "@pgard/git-history";
import type { AnalyzerContext } from "./types.js";

/**
 * PROTOTYPE (#414): secrets in the current files of a folder, for the code-only scan. Today the
 * secret rules (PG-SECRET-001/002) run only in the history scope, which reads Git objects; a
 * code-only scan reads no Git object, so it needs its own pass over the files on disk. It uses the
 * same detection as the pre-commit check (`scanStagedSecrets`, every line counted as new) and
 * never puts a secret value in a finding.
 *
 * Limits (a hostile tree cannot make it do unbounded work): at most `MAX_FILES` files, files up to
 * `MAX_FILE_BYTES`, depth `MAX_DEPTH`; symbolic links and special files are never followed or
 * read; a file with a NUL byte in its first 8 KiB is treated as binary and skipped. Anything left
 * out by a limit makes the area `partial` and is counted in its note.
 */
export const WORKING_TREE_SECRETS_AREA = "secrets:working-tree";
const MAX_FILES = 20_000;
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_DEPTH = 24;
const SKIPPED = new Set([".git", "node_modules", "bower_components", ".hg", ".svn"]);

export interface WorkingTreeSecretsOutput {
  findings: Finding[];
  coverage: Coverage[];
}

async function readTextFile(absolute: string): Promise<string | null> {
  const handle = await open(absolute, "r");
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.size > MAX_FILE_BYTES) return null;
    const buffer = Buffer.alloc(stat.size);
    const { bytesRead } = await handle.read(buffer, 0, stat.size, 0);
    const bytes = buffer.subarray(0, bytesRead);
    if (bytes.subarray(0, 8192).includes(0)) return null;
    return bytes.toString("utf8");
  } finally {
    await handle.close();
  }
}

export async function scanWorkingTreeSecrets(
  context: Pick<AnalyzerContext, "projectRoot" | "projectConfig" | "signal">,
): Promise<WorkingTreeSecretsOutput> {
  const excluded =
    context.projectConfig !== null && context.projectConfig.exclude.length > 0
      ? compilePathMatcher(context.projectConfig.exclude)
      : null;
  let filesRead = 0;
  let skippedLarge = 0;
  let skippedOther = 0;
  let hitLimit = false;
  const findings: Finding[] = [];
  const stack: Array<{ relative: string; depth: number }> = [{ relative: "", depth: 0 }];
  while (stack.length > 0) {
    if (context.signal?.aborted === true) throw new Error("aborted");
    const { relative, depth } = stack.pop() as { relative: string; depth: number };
    let entries;
    try {
      entries = await readdir(path.join(context.projectRoot, relative), { withFileTypes: true });
    } catch {
      skippedOther += 1;
      continue;
    }
    entries.sort((a, b) => (a.name < b.name ? 1 : a.name > b.name ? -1 : 0));
    for (const entry of entries) {
      const child = relative === "" ? entry.name : `${relative}/${entry.name}`;
      if (excluded?.matches(child) === true) continue;
      if (entry.isDirectory()) {
        if (SKIPPED.has(entry.name)) continue;
        if (depth + 1 > MAX_DEPTH) {
          hitLimit = true;
          continue;
        }
        stack.push({ relative: child, depth: depth + 1 });
        continue;
      }
      if (!entry.isFile()) continue; // symbolic links and special files are never read
      if (filesRead >= MAX_FILES) {
        hitLimit = true;
        continue;
      }
      const absolute = path.join(context.projectRoot, child);
      try {
        // Re-check with lstat: the entry may have been swapped for a link since readdir.
        const stat = await lstat(absolute);
        if (!stat.isFile()) continue;
        if (stat.size > MAX_FILE_BYTES) {
          skippedLarge += 1;
          continue;
        }
        const content = await readTextFile(absolute);
        filesRead += 1;
        if (content === null) continue;
        const scan = scanStagedSecrets([{ path: child, kind: "added", content, previous: null }]);
        findings.push(...scan.findings.map(relabel));
      } catch {
        skippedOther += 1;
      }
    }
  }
  const isPartial = hitLimit || skippedOther > 0;
  const parts = [`${filesRead} file(s) on disk checked for secrets.`];
  if (skippedLarge > 0) parts.push(`${skippedLarge} file(s) over 1 MiB were not read.`);
  if (skippedOther > 0) parts.push(`${skippedOther} file(s) or folder(s) could not be read.`);
  if (hitLimit) parts.push("A file-count or depth limit was reached; not every file was checked.");
  return {
    findings,
    coverage: [
      {
        area: WORKING_TREE_SECRETS_AREA,
        scope: "code",
        status: isPartial ? "partial" : "completed",
        ruleIds: ["PG-SECRET-001", "PG-SECRET-002"],
        note: parts.join(" "),
      },
    ],
  };
}

/** The pre-commit wording says "staged"; these findings come from the files on disk. */
function relabel(finding: Finding): Finding {
  // Never "tracked file" or "committed to Git": the file may never have been committed.
  const text = FINDING_TEXT_VARIANTS[finding.ruleId]?.working_tree;
  return {
    ...finding,
    ...(text === undefined
      ? {}
      : {
          title: text.title.en,
          impact: text.impact.en,
          recommendation: text.recommendation.en,
        }),
    evidence:
      finding.ruleId === "PG-SECRET-001"
        ? "environment file in the project folder (values not shown)"
        : finding.evidence.replace(" in a staged file ", " in a file on disk "),
  };
}
