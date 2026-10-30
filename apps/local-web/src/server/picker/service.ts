import { sanitizeDisplayText } from "@pgard/http-local";
import type { ScopeRoot } from "@pgard/result-store";
import type {
  PickerConfirmResponse,
  PickerRecentEntry,
  PickerRecentResponse,
  PickerScopeResponse,
  PickerSearchResponse,
} from "../../shared/picker-types.js";
import { ApiError } from "../routes/api-error.js";
import { resetProjectBoundState, type SessionState } from "../session/session-state.js";
import {
  buildCandidate,
  buildOutsideScope,
  buildUninspected,
  identityFingerprint,
  markCollisions,
  newId,
  shortenHome,
  type CandidateRecord,
} from "./candidates.js";
import type { JobOutcome, RunningJob } from "./inspector-host.js";
import { parseFolderName } from "./name.js";
import {
  ID_PATTERN,
  PICKER_LIMITS,
  type ChainSegment,
  type ChildMessage,
  type InspectorJob,
  type RawCandidate,
  type SearchSource,
} from "./protocol.js";
import type { PickerDeps, ProjectRecord, SearchRecord } from "./session.js";

/**
 * The operations behind the `/api/picker/*` routes and the identity re-checks before a run. Every
 * check the design asks for lives here: the browser sends a name, the server searches its own
 * scope, a candidate is a server-held record, and nothing is selected without a fresh inspection
 * that matches what the user saw.
 */

export interface PickerContext {
  state: SessionState;
  picker: PickerDeps | undefined;
  /** Wall-clock milliseconds (`deps.now`). */
  now: () => number;
}

export const ADD_SCOPE_COMMAND = "pgard web scope add <folder>";

const BUSY_MESSAGE =
  "Earlier searches are still stuck in the operating system (often a slow or disconnected network folder). Wait, or remove that folder from the search scope with `pgard web scope remove`.";

function requirePicker(context: PickerContext): PickerDeps {
  if (context.picker === undefined) throw new ApiError(500, "internal", "Internal error.");
  return context.picker;
}

function isSafeEpoch(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

/**
 * The epoch a request carried must be the current one. A malformed value is `bad_request`; a
 * missing or stale one is `project_changed` (another tab changed the project).
 */
export function requireCurrentEpoch(state: SessionState, epoch: unknown): void {
  if (epoch !== undefined && !isSafeEpoch(epoch)) {
    throw new ApiError(400, "bad_request", "epoch must be a positive integer.");
  }
  if (epoch !== state.projectEpoch) {
    throw new ApiError(
      409,
      "project_changed",
      "The project was changed in another window. This view is out of date.",
    );
  }
}

export function requireValidId(value: unknown): string {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) {
    throw new ApiError(400, "bad_id", "That id is not valid.");
  }
  return value;
}

function rootLabel(root: ScopeRoot, homeDir: string): string {
  return sanitizeDisplayText(shortenHome(root.path, homeDir), PICKER_LIMITS.maxDisplayPathLength);
}

function pickerRoots(context: PickerContext): SessionState["picker"]["roots"] {
  const deps = requirePicker(context);
  const session = context.state.picker;
  if (session.roots.length === 0 && deps.roots.length > 0) {
    session.roots = deps.roots.map((root) => ({
      id: newId(),
      label: rootLabel(root, deps.homeDir),
      root,
      enabled: true,
    }));
  }
  return session.roots;
}

export function getScope(context: PickerContext): PickerScopeResponse {
  return scopeResponse(context);
}

function scopeResponse(context: PickerContext): PickerScopeResponse {
  return {
    roots: pickerRoots(context).map(({ id, label, enabled }) => ({ id, label, enabled })),
    limits: {
      minTypedNameLength: PICKER_LIMITS.minTypedNameLength,
      maxNameLength: PICKER_LIMITS.maxNameUnits,
      maxDepth: PICKER_LIMITS.depth,
      maxCandidates: PICKER_LIMITS.maxCandidates,
      softBudgetSeconds: PICKER_LIMITS.softBudgetMs / 1000,
    },
    addCommand: ADD_SCOPE_COMMAND,
  };
}

/** Session-only on/off. It cannot add or change a path. */
export function toggleRoot(
  context: PickerContext,
  rootId: unknown,
  enabled: unknown,
): PickerScopeResponse {
  const id = requireValidId(rootId);
  if (typeof enabled !== "boolean") {
    throw new ApiError(400, "bad_request", "enabled must be true or false.");
  }
  const root = pickerRoots(context).find((entry) => entry.id === id);
  if (root === undefined) throw new ApiError(404, "not_found", "Unknown search folder.");
  root.enabled = enabled;
  return scopeResponse(context);
}

function enabledRoots(context: PickerContext): ScopeRoot[] {
  return pickerRoots(context)
    .filter((root) => root.enabled)
    .map((root) => root.root);
}

// --- Search -----------------------------------------------------------------------------------

function pruneCandidates(context: PickerContext): void {
  const { candidates } = context.state.picker;
  const now = context.now();
  for (const [id, record] of candidates) {
    if (now < record.createdAt || now - record.createdAt > PICKER_LIMITS.candidateWindowMs) {
      candidates.delete(id);
    }
  }
  while (candidates.size > PICKER_LIMITS.maxCandidateRecords) {
    const oldest = candidates.keys().next().value;
    if (oldest === undefined) break;
    candidates.delete(oldest);
  }
}

function pruneSearches(context: PickerContext): void {
  const { searches } = context.state.picker;
  while (searches.size > PICKER_LIMITS.maxKeptSearches) {
    const oldest = [...searches.values()].find((search) => search.running === null);
    if (oldest === undefined) break;
    searches.delete(oldest.id);
  }
}

function toSearchResponse(search: SearchRecord): PickerSearchResponse {
  return {
    status: search.status,
    stoppedAfterSeconds: search.stoppedAfterSeconds,
    stoppedBy: search.stoppedBy,
    uninspected: search.uninspected,
    visited: search.visited,
    candidates: search.candidates,
    skipped: search.skipped,
  };
}

export function startSearch(
  context: PickerContext,
  input: { source: unknown; name: unknown; epoch: unknown },
): { searchId: string; status: "running" } {
  const deps = requirePicker(context);
  const { state } = context;
  if (input.source !== "drop" && input.source !== "typed") {
    throw new ApiError(400, "bad_source", "source must be drop or typed.");
  }
  const source: SearchSource = input.source;
  const parsed = parseFolderName(input.name, source);
  if (!parsed.ok) throw new ApiError(400, "bad_name", parsed.message);
  requireCurrentEpoch(state, input.epoch);
  const now = context.now();
  const last = state.picker.lastSearchAt;
  // A clock that moved back gives a negative difference, which also counts as too soon.
  if (last !== null && now - last < PICKER_LIMITS.minSearchIntervalMs) {
    throw new ApiError(429, "search_too_soon", "Wait a second between searches.");
  }
  const roots = enabledRoots(context);
  const epochAtStart = state.projectEpoch;
  const search: SearchRecord = {
    id: newId(),
    status: "running",
    startedAt: now,
    visited: 0,
    stoppedAfterSeconds: null,
    stoppedBy: null,
    uninspected: 0,
    skipped: [],
    candidates: [],
    running: null,
  };
  const found = new Map<number, { rootIndex: number; segments: ChainSegment[] }>();
  const inspected = new Map<number, RawCandidate>();
  let done: Extract<ChildMessage, { t: "done" }> | null = null;
  const job: InspectorJob = {
    kind: "search",
    roots,
    name: parsed.name,
    source,
    platform: deps.platform,
  };
  let running: RunningJob | null = null;
  if (roots.length > 0) {
    running = deps.inspector.run(job, {
      hardMs: PICKER_LIMITS.hardBudgetMs,
      onMessage: (message) => {
        if (message.t === "visited") search.visited = message.n;
        else if (message.t === "found") {
          // At most one entry per key and never more than the candidate limit.
          if (!found.has(message.key) && found.size < PICKER_LIMITS.maxCandidates) {
            found.set(message.key, { rootIndex: message.rootIndex, segments: message.segments });
          }
        } else if (message.t === "inspected") {
          // An inspection answers a folder the walk reported: same key, same root, same chain.
          const entry = found.get(message.key);
          if (
            entry !== undefined &&
            !inspected.has(message.key) &&
            entry.rootIndex === message.candidate.rootIndex &&
            entry.segments.length === message.candidate.segments.length &&
            entry.segments.every((segment, index) => {
              const other = message.candidate.segments[index];
              return (
                other?.name === segment.name &&
                other.dev === segment.dev &&
                other.ino === segment.ino
              );
            })
          ) {
            inspected.set(message.key, message.candidate);
          }
        } else if (message.t === "done") done = message;
      },
    });
    if (running === null) throw new ApiError(503, "inspector_busy", BUSY_MESSAGE);
  }
  // Starting a search cancels the previous one.
  const previous =
    state.picker.currentSearchId === null
      ? undefined
      : state.picker.searches.get(state.picker.currentSearchId);
  if (previous?.running) {
    previous.running.cancel();
    previous.running = null;
    previous.status = "cancelled";
  }
  state.picker.lastSearchAt = now;
  state.picker.currentSearchId = search.id;
  state.picker.searches.set(search.id, search);
  if (running === null) {
    search.status = "done";
    pruneSearches(context);
    return { searchId: search.id, status: "running" };
  }
  search.running = running;
  void running.result.then((outcome) => {
    if (search.status !== "running") return; // cancelled or replaced meanwhile
    search.running = null;
    if (state.picker.searches.get(search.id) !== search) return;
    if (state.projectEpoch !== epochAtStart) {
      // Search completion is a handler like any other: the project changed under it.
      search.status = "cancelled";
      return;
    }
    finishSearch(context, search, job, outcome, found, inspected, done);
  });
  pruneSearches(context);
  return { searchId: search.id, status: "running" };
}

function finishSearch(
  context: PickerContext,
  search: SearchRecord,
  job: Extract<InspectorJob, { kind: "search" }>,
  outcome: JobOutcome,
  found: Map<number, { rootIndex: number; segments: ChainSegment[] }>,
  inspected: Map<number, RawCandidate>,
  done: Extract<ChildMessage, { t: "done" }> | null,
): void {
  const deps = requirePicker(context);
  if (outcome.status === "killed" && outcome.reason !== "deadline") {
    search.status = "cancelled";
    return;
  }
  if (outcome.status === "failed") {
    search.status = "failed";
    return;
  }
  const now = context.now();
  const records: CandidateRecord[] = [];
  for (const [key, entry] of [...found].sort((a, b) => a[0] - b[0])) {
    const root = job.roots[entry.rootIndex];
    if (root === undefined) continue;
    const raw = inspected.get(key);
    records.push(
      raw === undefined
        ? buildUninspected({ root, segments: entry.segments, homeDir: deps.homeDir, now })
        : buildCandidate({
            raw,
            root,
            source: "scope",
            entryId: null,
            homeDir: deps.homeDir,
            now,
          }),
    );
  }
  markCollisions(records);
  for (const record of records) context.state.picker.candidates.set(record.id, record);
  pruneCandidates(context);
  search.candidates = records.map((record) => record.dto);
  search.uninspected = records.filter((r) => r.dto.blocked?.code === "not_inspected").length;
  search.skipped = done?.skipped ?? [];
  if (done !== null) search.visited = done.visited;
  if (outcome.status === "killed" || done?.stoppedBy != null || search.uninspected > 0) {
    search.status = "partial";
    search.stoppedBy = outcome.status === "killed" ? "time" : (done?.stoppedBy ?? "time");
    search.stoppedAfterSeconds =
      outcome.status === "killed"
        ? PICKER_LIMITS.hardBudgetMs / 1000
        : Math.round(((done?.elapsedMs ?? 0) / 1000) * 10) / 10;
  } else {
    search.status = "done";
  }
}

export function getSearch(context: PickerContext, id: unknown): PickerSearchResponse {
  const searchId = requireValidId(id);
  const search = context.state.picker.searches.get(searchId);
  if (search === undefined) throw new ApiError(404, "unknown_search", "That search is not known.");
  pruneCandidates(context);
  return toSearchResponse(search);
}

export function cancelSearch(context: PickerContext, id: unknown): { status: string } {
  const searchId = requireValidId(id);
  const search = context.state.picker.searches.get(searchId);
  // Cancelling a finished or unknown search is a no-op.
  if (search === undefined) return { status: "cancelled" };
  if (search.status === "running") {
    search.running?.cancel();
    search.running = null;
    search.status = "cancelled";
  }
  return { status: search.status };
}

// --- Recent list ------------------------------------------------------------------------------

function recentEntryOf(
  record: CandidateRecord,
  entryId: string,
  lastUsedAt: string,
): PickerRecentEntry {
  return { ...record.dto, entryId, lastUsedAt };
}

export async function getRecent(context: PickerContext): Promise<PickerRecentResponse> {
  const deps = requirePicker(context);
  const { recent } = context.state.picker;
  if (deps.storage === null) return { entries: [], validating: false, ignored: false };
  const now = context.now();
  const cached = (): PickerRecentResponse => ({
    entries: recent.entries,
    validating: recent.run !== null,
    ignored: recent.ignored,
  });
  if (recent.run !== null) return cached();
  if (
    recent.validatedAt !== null &&
    now >= recent.validatedAt &&
    now - recent.validatedAt < PICKER_LIMITS.recentCacheMs
  ) {
    return cached();
  }
  // At most one revalidation per second (a clock that moved back counts as too soon).
  if (recent.startedAt !== null && now - recent.startedAt < PICKER_LIMITS.recentMinIntervalMs) {
    return cached();
  }
  recent.startedAt = now;
  const read = await deps.storage.readRecent();
  if (recent.run !== null) return cached();
  if (read.status !== "ok" || read.value.length === 0) {
    recent.entries = [];
    recent.ignored = read.status === "ignored";
    recent.validatedAt = context.now();
    return cached();
  }
  recent.ignored = false;
  const roots = enabledRoots(context);
  const stored = read.value;
  const job: InspectorJob = {
    kind: "recent",
    roots,
    entries: stored.map(({ entryId, path }) => ({ entryId, path })),
  };
  const outcomes = new Map<string, Extract<ChildMessage, { t: "recent" }>["outcome"]>();
  const running = deps.inspector.run(job, {
    hardMs: PICKER_LIMITS.hardBudgetMs,
    onMessage: (message) => {
      if (message.t === "recent") outcomes.set(message.entryId, message.outcome);
    },
  });
  if (running === null) throw new ApiError(503, "inspector_busy", BUSY_MESSAGE);
  recent.run = running;
  void running.result.then((outcome) => {
    if (recent.run !== running) return;
    recent.run = null;
    if (outcome.status === "killed" && outcome.reason !== "deadline") return;
    const at = context.now();
    const records: CandidateRecord[] = [];
    const entries: PickerRecentEntry[] = [];
    for (const entry of stored) {
      const result = outcomes.get(entry.entryId) ?? { status: "unreadable" as const };
      let record: CandidateRecord;
      if (result.status === "candidate") {
        const root = roots[result.candidate.rootIndex];
        record =
          root === undefined
            ? buildOutsideScope({
                storedPath: entry.path,
                homeDir: deps.homeDir,
                entryId: entry.entryId,
                now: at,
                outcome: "outside_scope",
              })
            : buildCandidate({
                raw: result.candidate,
                root,
                source: "recent",
                entryId: entry.entryId,
                homeDir: deps.homeDir,
                now: at,
              });
      } else {
        record = buildOutsideScope({
          storedPath: entry.path,
          homeDir: deps.homeDir,
          entryId: entry.entryId,
          now: at,
          outcome: result.status,
        });
      }
      records.push(record);
      entries.push(recentEntryOf(record, entry.entryId, entry.lastUsedAt));
    }
    markCollisions(records);
    for (const record of records) context.state.picker.candidates.set(record.id, record);
    pruneCandidates(context);
    recent.entries = entries;
    recent.validatedAt = at;
  });
  return cached();
}

export async function removeRecent(
  context: PickerContext,
  entryId: unknown,
): Promise<{ entries: PickerRecentEntry[] }> {
  const deps = requirePicker(context);
  const id = requireValidId(entryId);
  const { recent } = context.state.picker;
  recent.entries = recent.entries.filter((entry) => entry.entryId !== id);
  if (deps.storage === null) return { entries: recent.entries };
  const read = await deps.storage.readRecent();
  // An unreadable or newer file is never overwritten.
  if (read.status === "ok" && read.value.some((entry) => entry.entryId === id)) {
    await deps.storage.writeRecent(read.value.filter((entry) => entry.entryId !== id));
  }
  return { entries: recent.entries };
}

async function recordRecent(context: PickerContext, record: CandidateRecord): Promise<void> {
  const deps = requirePicker(context);
  if (deps.storage === null || record.repo === null || record.isChosenFolder === true) return;
  const read = await deps.storage.readRecent();
  if (read.status === "ignored") return; // never overwritten
  const existing = read.status === "ok" ? read.value : [];
  const previous = existing.find((entry) => entry.path === record.path);
  const entry = {
    entryId: previous?.entryId ?? newId(),
    path: record.path,
    repo: `${record.repo.owner}/${record.repo.name}`,
    lastUsedAt: new Date(context.now()).toISOString(),
  };
  await deps.storage.writeRecent([entry, ...existing.filter((item) => item.path !== record.path)]);
  context.state.picker.recent.validatedAt = null;
}

// --- Inspection jobs --------------------------------------------------------------------------

type InspectResult =
  { kind: "ok"; candidate: RawCandidate } | { kind: "changed" } | { kind: "unreadable" };

async function runInspect(
  context: PickerContext,
  job: Extract<InspectorJob, { kind: "inspect" }>,
  hardMs: number,
): Promise<InspectResult> {
  const deps = requirePicker(context);
  let candidate: RawCandidate | null = null;
  let isChanged = false;
  const running = deps.inspector.run(job, {
    hardMs,
    onMessage: (message) => {
      if (message.t === "inspected") candidate = message.candidate;
      else if (message.t === "changed") isChanged = true;
    },
  });
  if (running === null) throw new ApiError(503, "inspector_busy", BUSY_MESSAGE);
  const outcome = await running.result;
  if (outcome.status !== "finished") return { kind: "unreadable" };
  if (isChanged || candidate === null) return { kind: "changed" };
  return { kind: "ok", candidate };
}

const CHANGED_MESSAGE = "The folder changed since you looked at it. Choose it again.";

function assertProjectUnchanged(
  context: PickerContext,
  project: ProjectRecord | null,
  epoch: number,
): void {
  if (context.state.project !== project || context.state.projectEpoch !== epoch) {
    throw new ApiError(
      409,
      "project_changed",
      "The project changed while this was running; the result was discarded.",
    );
  }
}

function requireNothingRunning(state: SessionState): void {
  if (state.scan.status === "running") {
    throw new ApiError(409, "scan_running", "A scan is already running.");
  }
  if (state.auth.status === "running" || state.ownerApprovalRecheck) {
    throw new ApiError(
      409,
      "auth_running",
      "An authorization check is running. Cancel it first, then change the project.",
    );
  }
}

/**
 * Before every verify, owner-approval re-check and scan in picker mode: repeats the identity
 * chain and the ownership and write-bit checks of the confirmed project in the inspector, under
 * a short budget. Anything that differs, or could not be read in time, stops the run before it
 * starts. The main process never makes these fs calls itself.
 */
export async function recheckProjectIdentity(
  context: PickerContext,
  project: ProjectRecord,
  epoch: number,
  /** Only a code-only scan, and the simple screen's gate-first scan, accept a `folder` project. */
  allowFolder = false,
): Promise<void> {
  const identity = project.identity;
  if (identity === null) return; // fixed mode: the launcher confirmed the root
  if (identity.kind === "folder") {
    if (!allowFolder) {
      throw new ApiError(
        409,
        "code_only_project",
        "This folder can only get a code-only scan: it is not a GitHub repository PGARD can verify.",
      );
    }
    const folder = await runInspect(
      context,
      { kind: "inspect", root: identity.root, segments: identity.segments, mode: "folder" },
      PICKER_LIMITS.recheckBudgetMs,
    );
    assertProjectUnchanged(context, project, epoch);
    if (folder.kind === "unreadable") {
      throw new ApiError(
        409,
        "unreadable",
        "The project folder could not be read in time. Nothing was started; try again.",
      );
    }
    if (
      folder.kind === "changed" ||
      folder.candidate.block !== null ||
      identityFingerprint(identity.root, folder.candidate.segments, null) !== identity.fingerprint
    ) {
      throw new ApiError(409, "candidate_changed", CHANGED_MESSAGE);
    }
    return;
  }
  const result = await runInspect(
    context,
    { kind: "inspect", root: identity.root, segments: identity.segments, mode: "recheck" },
    PICKER_LIMITS.recheckBudgetMs,
  );
  assertProjectUnchanged(context, project, epoch);
  if (result.kind === "unreadable") {
    throw new ApiError(
      409,
      "unreadable",
      "The project folder could not be read in time. Nothing was started; try again.",
    );
  }
  if (
    result.kind === "changed" ||
    result.candidate.block !== null ||
    result.candidate.gitIdentity === null ||
    identityFingerprint(identity.root, result.candidate.segments, result.candidate.gitIdentity) !==
      identity.fingerprint
  ) {
    throw new ApiError(409, "candidate_changed", CHANGED_MESSAGE);
  }
}

// --- Confirm and clear ------------------------------------------------------------------------

export async function confirmCandidate(
  context: PickerContext,
  input: { candidateId: unknown; shown: unknown; epoch: unknown },
): Promise<PickerConfirmResponse> {
  const { state } = context;
  const candidateId = requireValidId(input.candidateId);
  if (typeof input.shown !== "string" || input.shown.length > 64) {
    throw new ApiError(400, "bad_request", "shown must be the fingerprint the page displayed.");
  }
  requireCurrentEpoch(state, input.epoch);
  const record = state.picker.candidates.get(candidateId);
  if (record === undefined) {
    throw new ApiError(404, "unknown_candidate", "That candidate is not known. Search again.");
  }
  const selected = state.project;
  if (
    selected !== null &&
    selected.candidateId === record.id &&
    selected.identity?.fingerprint === record.fingerprint &&
    record.shown === input.shown
  ) {
    // Idempotent: the same candidate confirmed again gives the same result.
    return projectResponse(state, selected);
  }
  const now = context.now();
  if (now < record.createdAt || now - record.createdAt > PICKER_LIMITS.candidateWindowMs) {
    state.picker.candidates.delete(record.id);
    throw new ApiError(409, "candidate_expired", "The confirmation expired. Search again.");
  }
  if (record.isFolderOnly === true) {
    return confirmFolderCandidate(context, record, input.shown, selected);
  }
  if (!record.isSelectable || record.repo === null || record.gitIdentity === null) {
    throw new ApiError(
      409,
      "candidate_blocked",
      `This folder cannot be selected (${record.dto.blocked?.code ?? "blocked"}).`,
    );
  }
  if (record.shown !== input.shown) throw new ApiError(409, "candidate_changed", CHANGED_MESSAGE);
  requireNothingRunning(state);
  const epochAtStart = state.projectEpoch;
  const result = await runInspect(
    context,
    { kind: "inspect", root: record.root, segments: record.segments, mode: "full" },
    PICKER_LIMITS.hardBudgetMs,
  );
  assertProjectUnchanged(context, selected, epochAtStart);
  requireNothingRunning(state);
  if (result.kind === "unreadable") {
    throw new ApiError(
      409,
      "unreadable",
      "The folder could not be read in time. Nothing was selected; search again.",
    );
  }
  if (result.kind !== "ok") throw new ApiError(409, "candidate_changed", CHANGED_MESSAGE);
  const fresh = result.candidate;
  const freshFingerprint =
    fresh.gitIdentity === null
      ? null
      : identityFingerprint(record.root, fresh.segments, fresh.gitIdentity);
  if (
    fresh.block !== null ||
    fresh.remote.status !== "github" ||
    fresh.remote.owner !== record.repo.owner ||
    fresh.remote.name !== record.repo.name ||
    freshFingerprint !== record.fingerprint ||
    fresh.gitIdentity === null
  ) {
    throw new ApiError(409, "candidate_changed", CHANGED_MESSAGE);
  }
  const name = sanitizeDisplayText(
    record.segments.at(-1)?.name ?? record.root.path.split("/").at(-1) ?? "",
    PICKER_LIMITS.maxDisplayNameLength,
  );
  const project: ProjectRecord = {
    root: record.path,
    name,
    repo: record.repo,
    repositoryId: null,
    identity: {
      root: record.root,
      segments: record.segments,
      gitIdentity: fresh.gitIdentity,
      fingerprint: record.fingerprint,
    },
    candidateId: record.id,
  };
  state.project = project;
  state.projectEpoch += 1;
  resetProjectBoundState(state);
  cancelRunningSearch(state);
  void recordRecent(context, record).catch(() => undefined);
  return projectResponse(state, project);
}

/**
 * #414: confirms a code-only folder (chosen in the OS dialog or pasted). The folder
 * chain is walked again and must match what the user saw, with safe ownership and write bits.
 */
async function confirmFolderCandidate(
  context: PickerContext,
  record: CandidateRecord,
  shown: string,
  selected: ProjectRecord | null,
): Promise<PickerConfirmResponse> {
  const { state } = context;
  if (record.shown !== shown) throw new ApiError(409, "candidate_changed", CHANGED_MESSAGE);
  requireNothingRunning(state);
  const epochAtStart = state.projectEpoch;
  const result = await runInspect(
    context,
    { kind: "inspect", root: record.root, segments: record.segments, mode: "folder" },
    PICKER_LIMITS.hardBudgetMs,
  );
  assertProjectUnchanged(context, selected, epochAtStart);
  requireNothingRunning(state);
  if (result.kind === "unreadable") {
    throw new ApiError(
      409,
      "unreadable",
      "The folder could not be read in time. Nothing was selected; try again.",
    );
  }
  if (
    result.kind !== "ok" ||
    result.candidate.block !== null ||
    identityFingerprint(record.root, result.candidate.segments, null) !== record.fingerprint
  ) {
    throw new ApiError(409, "candidate_changed", CHANGED_MESSAGE);
  }
  const project: ProjectRecord = {
    root: record.path,
    name: sanitizeDisplayText(
      record.segments.at(-1)?.name ?? record.root.path.split("/").at(-1) ?? "",
      PICKER_LIMITS.maxDisplayNameLength,
    ),
    repo: null,
    repositoryId: null,
    identity: {
      kind: "folder",
      ...(record.dto.codeOnly === undefined ? {} : { codeOnly: record.dto.codeOnly }),
      root: record.root,
      segments: record.segments,
      gitIdentity: null,
      fingerprint: record.fingerprint,
    },
    candidateId: record.id,
  };
  state.project = project;
  state.projectEpoch += 1;
  resetProjectBoundState(state);
  cancelRunningSearch(state);
  // No recent entry: the recent list holds GitHub repositories of the search scope only.
  return projectResponse(state, project);
}

function cancelRunningSearch(state: SessionState): void {
  for (const search of state.picker.searches.values()) {
    if (search.status === "running") {
      search.running?.cancel();
      search.running = null;
      search.status = "cancelled";
    }
  }
}

function projectResponse(state: SessionState, project: ProjectRecord): PickerConfirmResponse {
  return {
    project: {
      name: project.name,
      repo: project.repo === null ? null : `${project.repo.owner}/${project.repo.name}`,
    },
    projectEpoch: state.projectEpoch,
  };
}

/** Back to no project; the same reset as a confirm. Refused while a scan or check runs. */
export function clearProject(context: PickerContext, epoch: unknown): { projectEpoch: number } {
  const { state } = context;
  requireCurrentEpoch(state, epoch);
  if (state.project === null) return { projectEpoch: state.projectEpoch };
  requireNothingRunning(state);
  state.project = null;
  state.projectEpoch += 1;
  resetProjectBoundState(state);
  return { projectEpoch: state.projectEpoch };
}
