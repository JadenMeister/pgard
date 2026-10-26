import { listSupportedRules } from "./rules.js";

/**
 * How an incremental scan treats each rule. The classification is part of the correctness of
 * incremental scans, so a rule without an entry here makes every scan a full one
 * (`rules_unclassified`) and fails the test in `rule-locality.test.ts`. When unsure, pick the
 * stricter class: a rule that is not clearly file-local is `project-wide`.
 *
 * - `file-local`: the rule decides each finding from the text and path of one file only (no
 *   import, constant or type resolution into another file, no manifest, no configuration, no
 *   facts of other files). Its findings for a file whose SHA-256 did not change are reused, the
 *   file is not analyzed again.
 * - `project-wide`: a finding can depend on files other than the one it names (project facts
 *   such as library imports and session setup, manifests, the tracked tree). Such a rule is
 *   evaluated again on every scan from the facts of ALL files (reused files keep their stored
 *   facts, changed files supply fresh ones) and the current manifests, so a change anywhere is
 *   seen. Its findings are never copied from the stored result.
 * - `history-carried`: a rule of the Git history scan. Findings that name the tracked tree are
 *   recomputed from the scanned commit every time; findings about earlier commits are carried
 *   over only when the new commits provably leave them true (see `scanGitHistory`), otherwise
 *   the whole history is scanned again.
 */
export type RuleLocality = "file-local" | "project-wide" | "history-carried";

export interface RuleLocalityEntry {
  locality: RuleLocality;
  /** Why, in one sentence (documentation, and the reviewer's check). */
  reason: string;
}

const LOCAL = "Decided from the syntax tree and text of one file; reads nothing outside it.";
const GO_LOCAL = "Syntax-level patterns on one file's text; no cross-file data flow.";

export const RULE_LOCALITY: Readonly<Record<string, RuleLocalityEntry>> = {
  "PG-SQL-001": { locality: "file-local", reason: LOCAL },
  "PG-SQL-002": { locality: "file-local", reason: LOCAL },
  "PG-SQL-003": { locality: "file-local", reason: GO_LOCAL },
  "PG-SQL-004": { locality: "file-local", reason: GO_LOCAL },
  "PG-XSS-001": { locality: "file-local", reason: LOCAL },
  "PG-XSS-002": { locality: "file-local", reason: LOCAL },
  "PG-XSS-003": { locality: "file-local", reason: LOCAL },
  "PG-SSRF-001": { locality: "file-local", reason: LOCAL },
  "PG-CMD-001": { locality: "file-local", reason: LOCAL },
  "PG-CMD-002": { locality: "file-local", reason: GO_LOCAL },
  "PG-PATH-001": { locality: "file-local", reason: LOCAL },
  "PG-CRYPTO-001": { locality: "file-local", reason: LOCAL },
  "PG-CRYPTO-002": { locality: "file-local", reason: LOCAL },
  "PG-CRYPTO-003": { locality: "file-local", reason: LOCAL },
  "PG-AUTH-001": { locality: "file-local", reason: LOCAL },
  "PG-COOKIE-001": { locality: "file-local", reason: LOCAL },
  "PG-CSRF-001": {
    locality: "project-wide",
    reason:
      "Needs the session setup, CORS and CSRF-library imports of every file plus package.json dependencies: a change in any file or manifest can add or remove the finding.",
  },
  "PG-BRUTE-001": {
    locality: "project-wide",
    reason:
      "Reports authentication routes only when no rate-limiting library is imported or declared anywhere in the project.",
  },
  "PG-SECRET-001": {
    locality: "history-carried",
    reason:
      "Environment files in the tracked tree (recomputed) and in earlier commits (carried while the new commits add none).",
  },
  "PG-SECRET-002": {
    locality: "history-carried",
    reason: "Secrets in tracked files are read from the scanned commit's tree on every scan.",
  },
  "PG-SECRET-003": {
    locality: "history-carried",
    reason:
      "Whether an old secret is still present depends on the current tree and on every other commit, so it is carried only under the conditions of the history scan.",
  },
  "PG-HYGIENE-001": {
    locality: "history-carried",
    reason: "Derived from the tracked file list of the scanned commit on every scan.",
  },
};

/** Ids of supported rules that have no classification. Empty when the table is complete. */
export function unclassifiedRules(): string[] {
  return listSupportedRules()
    .map((rule) => rule.id)
    .filter((id) => !Object.hasOwn(RULE_LOCALITY, id));
}
