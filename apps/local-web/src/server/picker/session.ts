import type { ScopeRoot, WebStorage } from "@pgard/result-store";
import type {
  PickerCandidate,
  PickerRecentEntry,
  PickerSearchStatus,
} from "../../shared/picker-types.js";
import type { CandidateRecord } from "./candidates.js";
import type { InspectorHost, RunningJob } from "./inspector-host.js";
import type { ChainSegment, GitIdentity } from "./protocol.js";

/**
 * Picker state of one dashboard run: held in memory only, gone when the server stops. Ids are
 * random and only meaningful with the session token.
 */

/** The project the dashboard works on: fixed at start (`pgard dashboard`) or confirmed later. */
export interface ProjectRecord {
  /** Absolute project root. Server side only; never sent to the browser. */
  root: string;
  /** Display name (last segment, sanitized). */
  name: string;
  /** `owner/name` of the confirmed remote, or `null` in fixed mode. */
  repo: { owner: string; name: string } | null;
  /** GitHub's numeric id, pinned after the first check that returned it. */
  repositoryId: number | null;
  /** Picker mode only: the identity the confirm checked, compared again before every run. */
  identity: null | {
    root: ScopeRoot;
    segments: ChainSegment[];
    gitIdentity: GitIdentity;
    fingerprint: string;
  };
  /** The candidate this project was confirmed from (idempotent confirm). */
  candidateId: string | null;
}

export interface SearchRecord {
  id: string;
  status: PickerSearchStatus;
  startedAt: number;
  visited: number;
  stoppedAfterSeconds: number | null;
  stoppedBy: "time" | "entries" | "candidates" | null;
  uninspected: number;
  skipped: Array<{ reason: string; count: number }>;
  candidates: PickerCandidate[];
  running: RunningJob | null;
}

export interface PickerRoot {
  id: string;
  /** `~/code` style, sanitized. */
  label: string;
  root: ScopeRoot;
  enabled: boolean;
}

export interface PickerSession {
  roots: PickerRoot[];
  searches: Map<string, SearchRecord>;
  currentSearchId: string | null;
  lastSearchAt: number | null;
  candidates: Map<string, CandidateRecord>;
  recent: {
    entries: PickerRecentEntry[];
    validatedAt: number | null;
    startedAt: number | null;
    run: RunningJob | null;
    ignored: boolean;
  };
}

/** What the picker needs from the outside; injectable for tests. */
export interface PickerDeps {
  inspector: InspectorHost;
  /** `null` with `--no-store`: no recent list is read or written. */
  storage: WebStorage | null;
  roots: ScopeRoot[];
  homeDir: string;
  platform: string;
  /** For `~`-shortening and tests. */
  now?: () => number;
}

export function createPickerSession(): PickerSession {
  return {
    roots: [],
    searches: new Map(),
    currentSearchId: null,
    lastSearchAt: null,
    candidates: new Map(),
    recent: { entries: [], validatedAt: null, startedAt: null, run: null, ignored: false },
  };
}

/** Stops running searches and revalidations (their inspector processes are killed). */
export function cancelPickerWork(picker: PickerSession): void {
  for (const search of picker.searches.values()) {
    search.running?.cancel();
    search.running = null;
  }
  picker.recent.run?.cancel();
  picker.recent.run = null;
}
