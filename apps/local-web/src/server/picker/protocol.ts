import type { ScopeRoot } from "@pgard/result-store";
import { PICKER_BLOCK_CODES, type PickerBlockCode } from "../../shared/picker-types.js";

export { PICKER_BLOCK_CODES, type PickerBlockCode };

/**
 * Types and limits shared by the dashboard server and the inspector child process. The child
 * reads untrusted directories, so every message it sends back is validated by the server
 * against the strict schema in `validate-message.ts`.
 */

export const PICKER_LIMITS = {
  minTypedNameLength: 2,
  maxNameUnits: 255,
  depth: 4,
  maxDepth: 6,
  maxEntriesVisited: 50_000,
  maxEntriesPerDirectory: 5_000,
  maxCandidates: 20,
  /** Soft budget: stop walking and answer `partial`. */
  softBudgetMs: 5_000,
  /** Hard budget: the inspector's process group is killed. */
  hardBudgetMs: 8_000,
  /** Time for one Git call in the inspector. */
  gitTimeoutMs: 3_000,
  /** Budget for the identity re-check before a verify, owner-approval check or scan. */
  recheckBudgetMs: 2_000,
  minSearchIntervalMs: 1_000,
  recentCacheMs: 30_000,
  recentMinIntervalMs: 1_000,
  maxOutstandingChildren: 2,
  candidateWindowMs: 10 * 60 * 1000,
  maxCandidateRecords: 100,
  maxKeptSearches: 5,
  maxDisplayPathLength: 400,
  maxDisplayNameLength: 120,
} as const;

/** The limits as plain numbers, so a test can lower one. */
export type PickerLimits = { -readonly [K in keyof typeof PICKER_LIMITS]: number };

/** One directory below a scope root: its name from `readdir` and its identity from `lstat`. */
export interface ChainSegment {
  name: string;
  dev: number;
  ino: number;
}

export interface GitIdentity {
  gitDev: number;
  gitIno: number;
  configDev: number;
  configIno: number;
}

export type RemoteInfo =
  | { status: "github"; owner: string; name: string }
  | { status: "none" | "not_github" | "ambiguous" | "unreadable" };

/** What the inspector found out about one directory. The path is never trusted from the child. */
export interface RawCandidate {
  rootIndex: number;
  segments: ChainSegment[];
  gitIdentity: GitIdentity | null;
  remote: RemoteInfo;
  block: null | { code: PickerBlockCode; paths: string[] };
}

export type SearchSource = "drop" | "typed";

export type InspectorJob =
  | { kind: "search"; roots: ScopeRoot[]; name: string; source: SearchSource; platform: string }
  | {
      /** Re-inspect one candidate: `full` runs the Git calls, `recheck` only the identity chain. */
      kind: "inspect";
      root: ScopeRoot;
      segments: ChainSegment[];
      mode: "full" | "recheck";
    }
  | { kind: "recent"; roots: ScopeRoot[]; entries: Array<{ entryId: string; path: string }> };

export type StoppedBy = "time" | "entries" | "candidates" | null;

export type RecentOutcome =
  | { status: "candidate"; candidate: RawCandidate }
  | { status: "outside_scope" | "unreadable" | "gone" };

export type ChildMessage =
  | { t: "visited"; n: number }
  | { t: "found"; key: number; rootIndex: number; segments: ChainSegment[] }
  | { t: "inspected"; key: number; candidate: RawCandidate }
  | { t: "changed" }
  | { t: "recent"; entryId: string; outcome: RecentOutcome }
  | {
      t: "done";
      stoppedBy: StoppedBy;
      elapsedMs: number;
      visited: number;
      skipped: Array<{ reason: string; count: number }>;
    };

/** Fixed 22-character id: 128 random bits as base64url. */
export const ID_PATTERN = /^[A-Za-z0-9_-]{22}$/;
