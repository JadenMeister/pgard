/** OSV ecosystem names, exactly as used by the OSV export bucket. */
export type Ecosystem = "npm" | "Go";

export interface Dependency {
  ecosystem: Ecosystem;
  name: string;
  /** Exact resolved version as written in the lockfile. */
  version: string;
  /** True/false when the lockfile (or its manifest) tells; absent when it cannot. */
  direct?: boolean;
  /**
   * True when the lockfile says the package is needed only for development (npm `dev: true`);
   * absent when the lockfile does not say (yarn, pnpm 9, Go).
   */
  dev?: boolean;
  /** Repository-relative POSIX path of the lockfile the entry came from. */
  path: string;
}

export type LockfileKind = "npm" | "pnpm" | "yarn" | "go.mod" | "go.sum";

/** What a parser returns for one file. `notes` explain every gap in plain words. */
export interface ParsedLockfile {
  dependencies: Omit<Dependency, "path">[];
  notes: string[];
  /** False when the file was only partly understood (so "no findings" must not be read as clean). */
  isComplete: boolean;
}

export type CoverageStatus =
  | "parsed"
  | "partial"
  | "failed"
  | "too-large"
  | "unsupported"
  | "missing-lockfile"
  /** Not read because a limit (total bytes, packages, time) was reached. */
  | "not-read"
  /** A hard link to a lockfile that was already read; its content was checked once. */
  | "duplicate";

/** One coverage line: every lockfile or manifest found, and how far it could be used. */
export interface DependencyCoverage {
  path: string;
  kind: LockfileKind | "package.json" | "unsupported";
  status: CoverageStatus;
  dependencyCount: number;
  note: string | null;
}

export interface DependencyCollection {
  dependencies: Dependency[];
  coverage: DependencyCoverage[];
  /** A limit (files, bytes, packages or time) was reached; more lockfiles or packages may exist. */
  isTruncated: boolean;
  /** Which limits were reached, in plain words. Empty when none was. */
  limitNotes: string[];
  /** Bytes of lockfiles and manifests read (a hard link is read once). */
  bytesRead: number;
}

export interface CollectOptions {
  /** Aborting rejects the collection with an `AbortError`. */
  signal?: AbortSignal;
  /** Wall-clock budget in ms for the walk and the reads (default `COLLECT_TIME_BUDGET_MS`). */
  timeBudgetMs?: number;
  /** Injectable clock (ms) for tests. */
  now?: () => number;
  /** Lower limits for tests; the defaults are in `limits.ts`. */
  limits?: Partial<{
    totalBytes: number;
    totalDependencies: number;
    lockfileBytes: number;
    visitedEntries: number;
    lockfiles: number;
  }>;
}
