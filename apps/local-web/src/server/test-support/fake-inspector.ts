import type { ScopeRoot } from "@pgard/result-store";
import type { InspectorHost, JobOutcome, RunningJob } from "../picker/inspector-host.js";
import type {
  ChainSegment,
  ChildMessage,
  InspectorJob,
  RawCandidate,
  RecentOutcome,
  ResolveRefusal,
} from "../picker/protocol.js";

/**
 * A scripted stand-in for the inspector child process. In `auto` mode every job answers at once
 * from `world`; in `manual` mode a job stays open until the test drives it (`emit`, `finish`),
 * to test cancellation, deadlines and in-flight changes.
 */
export interface FakeRun {
  job: InspectorJob;
  options: { hardMs: number };
  isCancelled: boolean;
  emit: (message: ChildMessage) => void;
  finish: (outcome: JobOutcome) => void;
}

export interface FakeInspector extends InspectorHost {
  /** Candidates a search for each exact name finds. */
  repos: Map<string, RawCandidate[]>;
  /** What a `recent` job reports per stored path (default `outside_scope`). */
  recent: Map<string, RecentOutcome>;
  runs: FakeRun[];
  mode: "auto" | "manual";
  /** When true, `run` returns null (too many stuck children). */
  isBusy: boolean;
  /** Makes the next `inspect` jobs answer `changed`. */
  inspectChanged: boolean;
  /** Replaces what `inspect` answers for a candidate (to simulate a changed remote or mode). */
  inspectOverride: ((raw: RawCandidate) => RawCandidate) | null;
  /**
   * PROTOTYPE (#414): what a `resolve` job answers per path (default `missing`). A candidate is
   * also what later `inspect` jobs of its chain find.
   */
  resolved: Map<
    string,
    | { candidate: RawCandidate; folderBlock: RawCandidate["block"] }
    | { refused: ResolveRefusal; paths?: string[] }
  >;
  /** What a `folder` inspection answers as its block (default `null`). */
  folderBlock: RawCandidate["block"];
}

export function createFakeInspector(root: ScopeRoot): FakeInspector {
  const byKey = (segments: readonly ChainSegment[]): string =>
    segments.map((s) => s.name).join("/");
  const fake: FakeInspector = {
    repos: new Map(),
    recent: new Map(),
    runs: [],
    mode: "auto",
    isBusy: false,
    inspectChanged: false,
    inspectOverride: null,
    resolved: new Map(),
    folderBlock: null,
    outstandingCount: () => 0,
    stopAll: () => {
      for (const run of fake.runs)
        if (!run.isCancelled) run.finish({ status: "killed", reason: "shutdown" });
    },
    run: (job, options) => {
      if (fake.isBusy) return null;
      let settle: (outcome: JobOutcome) => void = () => undefined;
      const result = new Promise<JobOutcome>((resolve) => {
        settle = resolve;
      });
      let isSettled = false;
      const run: FakeRun = {
        job,
        options: { hardMs: options.hardMs },
        isCancelled: false,
        emit: (message) => {
          if (!isSettled) options.onMessage(message);
        },
        finish: (outcome) => {
          if (isSettled) return;
          isSettled = true;
          settle(outcome);
        },
      };
      fake.runs.push(run);
      const handle: RunningJob = {
        result,
        cancel: () => {
          run.isCancelled = true;
          run.finish({ status: "killed", reason: "cancelled" });
        },
      };
      if (fake.mode === "auto") {
        queueMicrotask(() => {
          answer(fake, job, run, byKey, root);
        });
      }
      return handle;
    },
  };
  return fake;
}

function answer(
  fake: FakeInspector,
  job: InspectorJob,
  run: FakeRun,
  byKey: (segments: readonly ChainSegment[]) => string,
  root: ScopeRoot,
): void {
  const done: ChildMessage = { t: "done", stoppedBy: null, elapsedMs: 12, visited: 3, skipped: [] };
  if (job.kind === "search") {
    const matches = fake.repos.get(job.name) ?? [];
    matches.forEach((candidate, key) => {
      run.emit({ t: "found", key, rootIndex: candidate.rootIndex, segments: candidate.segments });
    });
    matches.forEach((candidate, key) => run.emit({ t: "inspected", key, candidate }));
    run.emit(done);
  } else if (job.kind === "resolve") {
    const entry = fake.resolved.get(job.path);
    if (entry === undefined) run.emit({ t: "refused", reason: "missing", paths: [] });
    else if ("refused" in entry) {
      run.emit({ t: "refused", reason: entry.refused, paths: entry.paths ?? [] });
    } else {
      run.emit({
        t: "resolved",
        root,
        candidate: { ...entry.candidate, rootIndex: 0 },
        folderBlock: entry.folderBlock,
      });
    }
    run.emit(done);
  } else if (job.kind === "inspect") {
    const wanted = byKey(job.segments);
    const known = [
      ...[...fake.repos.values()].flat(),
      ...[...fake.resolved.values()].flatMap((entry) =>
        "candidate" in entry ? [entry.candidate] : [],
      ),
    ].find((c) => byKey(c.segments) === wanted);
    if (fake.inspectChanged || known === undefined) run.emit({ t: "changed" });
    else if (job.mode === "folder") {
      run.emit({
        t: "inspected",
        key: 0,
        candidate: {
          rootIndex: 0,
          segments: known.segments,
          gitIdentity: null,
          remote: { status: "unreadable" },
          block: fake.folderBlock,
        },
      });
    } else {
      const raw = fake.inspectOverride?.(known) ?? known;
      run.emit({
        t: "inspected",
        key: 0,
        candidate:
          job.mode === "recheck"
            ? { ...raw, remote: { status: "unreadable" }, rootIndex: 0 }
            : { ...raw, rootIndex: 0 },
      });
    }
    run.emit(done);
  } else {
    for (const entry of job.entries) {
      run.emit({
        t: "recent",
        entryId: entry.entryId,
        outcome: fake.recent.get(entry.path) ?? { status: "outside_scope" },
      });
    }
    run.emit(done);
  }
  run.finish({ status: "finished" });
  void root;
}

/** A selectable candidate under the fake root. */
export function repoCandidate(
  name: string,
  options: {
    parents?: string[];
    repo?: [string, string];
    ino?: number;
    block?: RawCandidate["block"];
    remote?: RawCandidate["remote"];
  } = {},
): RawCandidate {
  const [owner, repoName] = options.repo ?? ["acme", name];
  const ino = options.ino ?? 100 + name.length;
  const segments: ChainSegment[] = [...(options.parents ?? []), name].map((entry, index) => ({
    name: entry,
    dev: 1,
    ino: ino + index,
  }));
  return {
    rootIndex: 0,
    segments,
    gitIdentity: { gitDev: 1, gitIno: ino + 50, configDev: 1, configIno: ino + 51 },
    remote: options.remote ?? { status: "github", owner, name: repoName },
    block: options.block ?? null,
  };
}
