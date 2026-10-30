import type { Finding } from "@pgard/findings";
import { SECRET_KIND_LABEL, detectSecrets, isEnvironmentFile } from "./secret-patterns.js";
import { assessment, createFinding } from "./scan-history.js";
import type { StagedFile, StagedSkip } from "./staged.js";

/**
 * 1-based numbers of the lines of `current` that are new compared with `previous`: a line counts
 * as new when `previous` has no more unused copies of the same line (compared without trailing
 * whitespace). `null` for `previous` means every line is new. This is a line-level approximation
 * of a diff's added hunks that needs no `git diff`; a moved line is not new, an edited one is.
 */
export function addedLineNumbers(previous: string | null, current: string): Set<number> {
  const added = new Set<number>();
  const lines = current.split("\n");
  if (previous === null) {
    for (let index = 1; index <= lines.length; index += 1) added.add(index);
    return added;
  }
  const available = new Map<string, number>();
  for (const line of previous.split("\n")) {
    const key = line.trimEnd();
    available.set(key, (available.get(key) ?? 0) + 1);
  }
  lines.forEach((line, index) => {
    const key = line.trimEnd();
    const count = available.get(key) ?? 0;
    if (count > 0) available.set(key, count - 1);
    else added.add(index + 1);
  });
  return added;
}

/** True when any line from `first` to `last` (inclusive) is in `added`. */
export function spanHasAddedLine(added: ReadonlySet<number>, first: number, last: number): boolean {
  for (let line = first; line <= last; line += 1) {
    if (added.has(line)) return true;
  }
  return false;
}

export interface StagedSecretScan {
  findings: Finding[];
  /** Secrets that are in a staged file but not new in this commit. */
  preexisting: number;
}

/** A staged finding belongs to the code being committed, not to Git history. */
function withCodeSource(finding: Finding): Finding {
  return { ...finding, sources: ["code"] };
}

function envFileFinding(filePath: string): Finding {
  return withCodeSource(
    createFinding({
      ruleId: "PG-SECRET-001",
      path: filePath,
      line: null,
      commit: null,
      severity: "high",
      status: "confirmed",
      confidence: "high",
      evidence: "environment file is staged for commit (values not shown)",
      cause: "env-file-head",
    }),
  );
}

/**
 * Secrets in the new parts of the staged files (rules PG-SECRET-001 and PG-SECRET-002, the same
 * detection as for tracked files). A secret is new when HEAD's version of the file has no secret
 * with the same value, or when any line of the span it covers (a private key covers many) was
 * added or changed, so a changed key body under an unchanged header is still reported. A staged
 * `.env` file is reported when it is new in this commit. Values are never put in a finding.
 */
export function scanStagedSecrets(files: readonly StagedFile[]): StagedSecretScan {
  const findings: Finding[] = [];
  let preexisting = 0;
  for (const file of files) {
    if (isEnvironmentFile(file.path) && file.kind !== "modified") {
      findings.push(envFileFinding(file.path));
    }
    // UTF-16 files are read twice (as UTF-16 and as UTF-8), so a secret in either kind of part is
    // seen; one secret found by both readings is reported once.
    const seen = new Set<string>();
    const readings: [string, string | null][] = [[file.content, file.previous]];
    if (file.alternate !== undefined) {
      readings.push([file.alternate, file.previousAlternate ?? null]);
    }
    for (const [content, previous] of readings) {
      const thisReading = new Set<string>();
      // A renamed file carries its old text, so only edits made with the rename count as new.
      const added = addedLineNumbers(previous, content);
      const known =
        previous === null
          ? new Set<string>()
          : new Set(detectSecrets(previous, { path: file.path }).map((found) => found.value));
      // A new environment file is reported whole (PG-SECRET-001), so its generic per-line
      // credential matches are left out; provider-specific secrets are still reported.
      const omitGeneric = isEnvironmentFile(file.path) && file.kind !== "modified";
      for (const secret of detectSecrets(content, { path: file.path, omitGeneric })) {
        const key = `${secret.kind}\0${secret.value}`;
        // Skip a secret an earlier reading of this file already reported (a preexisting one does not
        // count, so a new copy of it in the other reading is still reported).
        if (seen.has(key)) continue;
        const lastLine = secret.line + (secret.value.match(/\n/g)?.length ?? 0);
        if (known.has(secret.value) && !spanHasAddedLine(added, secret.line, lastLine)) {
          preexisting += 1;
          continue;
        }
        thisReading.add(key);
        findings.push(
          withCodeSource(
            createFinding({
              ruleId: "PG-SECRET-002",
              path: file.path,
              line: secret.line,
              commit: null,
              ...assessment(secret),
              evidence:
                `${SECRET_KIND_LABEL[secret.kind]} in a staged file (value redacted)` +
                (secret.codeText === true
                  ? "; the value looks like code text inside a string literal (inferred)"
                  : ""),
              cause: `${secret.kind}:${secret.line}`,
            }),
          ),
        );
      }
      for (const key of thisReading) seen.add(key);
    }
  }
  return { findings, preexisting };
}

/**
 * The file-name check (PG-SECRET-001) for staged files whose content was not read as text
 * (binary, too large, unreadable, over a limit): a new `.env` file is reported by its name
 * whatever it holds.
 */
export function scanStagedPaths(skipped: readonly StagedSkip[]): Finding[] {
  return skipped
    .filter((item) => item.kind !== "modified" && isEnvironmentFile(item.path))
    .map((item) => envFileFinding(item.path));
}
