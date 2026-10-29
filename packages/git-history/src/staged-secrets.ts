import type { Finding } from "@pgard/findings";
import { SECRET_KIND_LABEL, detectSecrets, isEnvironmentFile } from "./secret-patterns.js";
import { assessment, createFinding } from "./scan-history.js";
import type { StagedFile } from "./staged.js";

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

export interface StagedSecretScan {
  findings: Finding[];
  /** Secrets that are in a staged file but on lines the commit does not change. */
  preexisting: number;
}

/**
 * Secrets in the new lines of the staged files (rules PG-SECRET-001 and PG-SECRET-002, the same
 * detection as for tracked files). A staged `.env` file is reported when it is new in this
 * commit. Values are never put in a finding.
 */
export function scanStagedSecrets(files: readonly StagedFile[]): StagedSecretScan {
  const findings: Finding[] = [];
  let preexisting = 0;
  for (const file of files) {
    if (isEnvironmentFile(file.path) && (file.kind !== "modified" || file.previous === null)) {
      findings.push(
        withCodeSource(
          createFinding({
            ruleId: "PG-SECRET-001",
            path: file.path,
            line: null,
            commit: null,
            severity: "high",
            status: "confirmed",
            confidence: "high",
            evidence: "environment file is staged for commit (values not shown)",
            cause: "env-file-head",
          }),
        ),
      );
    }
    // A renamed file carries its old text, so only edits made with the rename count as new.
    const added = addedLineNumbers(file.previous, file.content);
    for (const secret of detectSecrets(file.content, { path: file.path })) {
      if (!added.has(secret.line)) {
        preexisting += 1;
        continue;
      }
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
  }
  return { findings, preexisting };
}

/** A staged finding belongs to the code being committed, not to Git history. */
function withCodeSource(finding: Finding): Finding {
  return { ...finding, sources: ["code"] };
}
