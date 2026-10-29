/**
 * JSON shapes of the `pgard web` project picker. Browser-safe: types only. The browser sends a
 * folder name, never a path; everything here comes from the server's own walk and inspection.
 */
import type { ProjectInfo } from "./api-types.js";

export const PICKER_BLOCK_CODES = [
  "not_a_git_root",
  "no_commit_history",
  "isolation_failed",
  "no_remote",
  "remote_not_github",
  "remote_ambiguous",
  "remote_unreadable",
  "not_owned_by_you",
  "group_or_world_writable",
  "gitfile_unsupported",
  "git_dir_unsupported",
  "outside_scope",
  "unsafe_display",
  "not_inspected",
  "unreadable",
] as const;

export type PickerBlockCode = (typeof PICKER_BLOCK_CODES)[number];

export type PickerRemote =
  | { status: "github"; repo: string }
  | { status: "none" | "not_github" | "ambiguous" | "unreadable" };

export interface PickerCandidate {
  /** 22 characters of `[A-Za-z0-9_-]`, server-held, valid 10 minutes. */
  candidateId: string;
  name: string;
  /** The real path, `~`-shortened and sanitized. */
  displayPath: string;
  /** Set only when blocked as `unsafe_display`: non-printable characters as `\u{...}`. */
  displayPathEscaped: string | null;
  /** Same display path as another candidate: a short tag from the fingerprint. */
  collision: { tag: string } | null;
  /** Fingerprint of the identity chain and `owner/name`; echoed back on confirm. */
  shown: string;
  remote: PickerRemote;
  selectable: boolean;
  blocked: null | {
    code: PickerBlockCode;
    /** Every failing directory or file for ownership and write-bit blocks (shortened, sanitized). */
    paths: string[];
    /** Fixed English text; the page maps `code` to English or Korean. */
    reason: string;
    fix: string;
  };
  source: "scope" | "recent";
}

export interface PickerRecentEntry extends PickerCandidate {
  entryId: string;
  lastUsedAt: string;
}

export interface PickerScopeResponse {
  roots: Array<{ id: string; label: string; enabled: boolean }>;
  limits: {
    minTypedNameLength: number;
    maxNameLength: number;
    maxDepth: number;
    maxCandidates: number;
    softBudgetSeconds: number;
  };
  /** Fixed text for the page to show and copy. */
  addCommand: string;
}

export type PickerSearchStatus = "running" | "done" | "partial" | "cancelled" | "failed";

export interface PickerSearchResponse {
  status: PickerSearchStatus;
  stoppedAfterSeconds: number | null;
  /** What ended the search early: the time budget, the entry limit or the candidate limit. */
  stoppedBy: "time" | "entries" | "candidates" | null;
  uninspected: number;
  visited: number;
  candidates: PickerCandidate[];
  skipped: Array<{ reason: string; count: number }>;
}

export interface PickerRecentResponse {
  entries: PickerRecentEntry[];
  validating: boolean;
  /** The recent file was damaged or from a newer PGARD and is ignored. */
  ignored: boolean;
}

export interface PickerConfirmResponse {
  project: ProjectInfo;
  projectEpoch: number;
}
