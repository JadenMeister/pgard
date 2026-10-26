/** OSV ecosystem names, exactly as used by the OSV export bucket. */
export type Ecosystem = "npm" | "Go";

export interface Dependency {
  ecosystem: Ecosystem;
  name: string;
  /** Exact resolved version as written in the lockfile. */
  version: string;
  /** True/false when the lockfile (or its manifest) tells; absent when it cannot. */
  direct?: boolean;
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
  "parsed" | "partial" | "failed" | "too-large" | "unsupported" | "missing-lockfile";

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
  /** The file or lockfile limit was reached; more lockfiles may exist. */
  isTruncated: boolean;
}
