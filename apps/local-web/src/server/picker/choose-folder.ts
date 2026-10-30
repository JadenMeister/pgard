import path from "node:path";
import type {
  FolderRefusalCode,
  PickerBrowseResponse,
  PickerCandidate,
  PickerPathResponse,
} from "../../shared/picker-types.js";
import { ApiError } from "../routes/api-error.js";
import {
  buildCandidate,
  escapeForDisplay,
  identityFingerprint,
  sanitizedOrNull,
  shortenHome,
  shownFingerprint,
  type CandidateRecord,
} from "./candidates.js";
import type { PickerContext } from "./service.js";
import {
  PICKER_LIMITS,
  type PickerBlockCode,
  type RawCandidate,
  type ResolveRefusal,
} from "./protocol.js";
import type { ScopeRoot } from "@pgard/result-store";

/**
 * #414: choosing the folder with the OS folder dialog or by pasting its path, for the
 * one-screen code-only flow. The browser never sends a path to the dialog route; for the paste
 * route it sends the text the user pasted, which is resolved and checked in the inspector child
 * exactly like a search candidate (realpath, `lstat` chain, ownership and write bits, display
 * safety). A folder that is not a GitHub repository PGARD can verify is selectable for a
 * code-only scan only (`codeOnly`); every route that runs the authorization gate refuses it.
 */

export const MAX_PASTED_PATH = 4096;

/** Fixed English text per refusal; the page maps the code to English or Korean. */
export const FOLDER_REFUSAL_TEXT: Record<FolderRefusalCode, { reason: string; fix: string }> = {
  bad_path: {
    reason: "This is not a folder path.",
    fix: "Paste the full path, for example ~/code/my-app or /Users/you/code/my-app.",
  },
  missing: {
    reason: "This folder does not exist.",
    fix: "Check the path, or use Choose folder.",
  },
  not_a_directory: {
    reason: "This is a file, not a folder.",
    fix: "Choose the project's folder.",
  },
  too_broad: {
    reason: "This is your home folder or a system folder, not a project.",
    fix: "Choose the project's own folder, for example ~/code/my-app.",
  },
  too_deep: {
    reason: "This folder is nested too deeply to check.",
    fix: "Choose a folder closer to your home folder.",
  },
  unreadable: {
    reason: "This folder could not be read in time.",
    fix: "Try again; a slow or disconnected network folder can cause this.",
  },
  not_owned_by_you: {
    reason: "This folder, or a folder above it, belongs to another user.",
    fix: "Copy the project into your own folder.",
  },
  group_or_world_writable: {
    reason: "Another user could change this folder or a folder above it.",
    fix: "Remove group and other write access (chmod go-w), or copy the project into your own folder.",
  },
  git_directory: {
    reason: "This is Git's own data folder (.git), not the project's files.",
    fix: "Choose the project's folder, the one that contains .git.",
  },
};

/** Blocks that only concern Git or the remote: the folder still gets a code-only scan. */
const CODE_ONLY_REASON: Partial<Record<PickerBlockCode, NonNullable<PickerCandidate["codeOnly"]>>> =
  {
    not_a_git_root: "not_git",
    no_commit_history: "not_git",
    no_remote: "no_github_remote",
    remote_not_github: "no_github_remote",
    remote_ambiguous: "no_github_remote",
    remote_unreadable: "no_github_remote",
    isolation_failed: "git_unsupported",
    gitfile_unsupported: "git_unsupported",
    git_dir_unsupported: "git_unsupported",
    // A slow or blocked Git, or `.git` metadata another user could change, matters only to the
    // authorized flow; the code-only scan reads no Git data.
    unreadable: "git_unsupported",
    not_owned_by_you: "git_unsupported",
    group_or_world_writable: "git_unsupported",
  };

function refusal(code: FolderRefusalCode, paths: string[] = []): PickerPathResponse {
  return { candidate: null, refusal: { code, paths, ...FOLDER_REFUSAL_TEXT[code] } };
}

/**
 * A refused path as the page may show it: `~`-shortened, and through the same display-safety
 * check as a candidate's path. A name with control, invisible or look-alike characters (or a very
 * long one) is shown escaped (`\u{202e}`), never as is.
 */
function displayPath(entry: string, homeDir: string): string {
  const short = shortenHome(entry, homeDir);
  return sanitizedOrNull(short, PICKER_LIMITS.maxDisplayPathLength) ?? escapeForDisplay(short);
}

const FOLDER_CHAIN_REFUSALS: ReadonlySet<string> = new Set<FolderRefusalCode>([
  "not_owned_by_you",
  "group_or_world_writable",
]);

/** `~` and `~/...` expand to the home folder; `~user` and relative paths are refused. */
export function expandPastedPath(raw: unknown, homeDir: string): string | null {
  if (typeof raw !== "string") return null;
  const text = raw.trim();
  if (text.length === 0 || text.length > MAX_PASTED_PATH || text.includes("\0")) return null;
  let expanded = text;
  if (text === "~" || text.startsWith("~/")) {
    if (!path.posix.isAbsolute(homeDir)) return null;
    expanded = path.posix.join(homeDir, text.slice(1));
  }
  if (!path.posix.isAbsolute(expanded)) return null;
  return path.posix.normalize(expanded).replace(/(.)\/$/, "$1");
}

/**
 * The candidate for a resolved folder: a normal one when it is a selectable GitHub repository;
 * otherwise a code-only one when only Git or the remote stand in the way and the folder chain is
 * safe; otherwise blocked with the reason.
 */
function toRecord(
  context: PickerContext,
  root: ScopeRoot,
  raw: RawCandidate,
  folderBlock: RawCandidate["block"],
): CandidateRecord {
  const picker = context.picker;
  const homeDir = picker?.homeDir ?? "";
  const now = context.now();
  const build = (candidate: RawCandidate): CandidateRecord =>
    buildCandidate({ raw: candidate, root, source: "scope", entryId: null, homeDir, now });
  if (folderBlock !== null) return build({ ...raw, block: folderBlock });
  const record = build(raw);
  if (record.isSelectable) return record;
  const reason = raw.block === null ? undefined : CODE_ONLY_REASON[raw.block.code];
  // `unsafe_display` (set by buildCandidate) is never tolerated.
  if (reason === undefined || record.dto.blocked?.code === "unsafe_display") return record;
  const fingerprint = identityFingerprint(root, raw.segments, null);
  const shown = shownFingerprint(fingerprint, null);
  return {
    ...record,
    repo: null,
    gitIdentity: null,
    fingerprint,
    shown,
    isSelectable: true,
    isFolderOnly: true,
    dto: {
      ...record.dto,
      shown,
      remote: raw.remote.status === "github" ? { status: "unreadable" } : record.dto.remote,
      selectable: true,
      blocked: null,
      codeOnly: reason,
    },
  };
}

function storeRecord(context: PickerContext, record: CandidateRecord): void {
  const { candidates } = context.state.picker;
  candidates.set(record.id, record);
  while (candidates.size > PICKER_LIMITS.maxCandidateRecords) {
    const oldest = candidates.keys().next().value;
    if (oldest === undefined) break;
    candidates.delete(oldest);
  }
}

/** Resolves one absolute path in the inspector child and turns it into a candidate. */
export async function resolveFolderPath(
  context: PickerContext,
  absolutePath: string,
): Promise<PickerPathResponse> {
  const picker = context.picker;
  if (picker === undefined) throw new ApiError(500, "internal", "Internal error.");
  const got: {
    resolved: {
      root: ScopeRoot;
      candidate: RawCandidate;
      folderBlock: RawCandidate["block"];
      insideRepository: boolean;
    } | null;
    refused: { reason: ResolveRefusal; paths: string[] } | null;
  } = { resolved: null, refused: null };
  const running = picker.inspector.run(
    { kind: "resolve", path: absolutePath, homeDir: picker.homeDir },
    {
      hardMs: PICKER_LIMITS.hardBudgetMs,
      onMessage: (message) => {
        if (message.t === "resolved") {
          got.resolved = {
            root: message.root,
            candidate: message.candidate,
            folderBlock: message.folderBlock,
            insideRepository: message.insideRepository === true,
          };
        } else if (message.t === "refused") {
          got.refused = { reason: message.reason, paths: message.paths };
        }
      },
    },
  );
  if (running === null) {
    throw new ApiError(
      503,
      "inspector_busy",
      "Earlier folder checks are still running. Wait a moment, then try again.",
    );
  }
  const outcome = await running.result;
  const done = got.resolved;
  const no = got.refused;
  if (outcome.status !== "finished") return refusal("unreadable");
  if (no !== null) {
    return refusal(
      no.reason,
      no.paths.map((entry) => displayPath(entry, picker.homeDir)),
    );
  }
  if (done === null) return refusal("unreadable");
  // A folder chain another user owns or could change is refused outright, with the folder's own
  // wording (the candidate wording also mentions `.git`, which this check never looked at).
  const chain = done.folderBlock;
  if (chain !== null && FOLDER_CHAIN_REFUSALS.has(chain.code)) {
    return refusal(
      chain.code as FolderRefusalCode,
      chain.paths.map((entry) => displayPath(entry, picker.homeDir)),
    );
  }
  const built = toRecord(context, done.root, done.candidate, done.folderBlock);
  const record = {
    ...built,
    dto: done.insideRepository ? { ...built.dto, insideRepository: true as const } : built.dto,
    isChosenFolder: true,
  };
  storeRecord(context, record);
  return { candidate: record.dto, refusal: null };
}

/** `POST /api/picker/path`: a pasted path. */
export async function choosePastedPath(
  context: PickerContext,
  raw: unknown,
): Promise<PickerPathResponse> {
  const picker = context.picker;
  if (picker === undefined) throw new ApiError(500, "internal", "Internal error.");
  const absolute = expandPastedPath(raw, picker.homeDir);
  if (absolute === null) return refusal("bad_path");
  return resolveFolderPath(context, absolute);
}

/** The prompt of the OS dialog: PGARD's own text, never from the request. */
const DIALOG_PROMPT = {
  en: "Choose the project folder to scan",
  ko: "검사할 프로젝트 폴더를 선택하세요",
} as const;

/** After a dialog closes, the next one may open only this much later (no overlapping windows). */
export const DIALOG_REOPEN_PAUSE_MS = 1_500;

/**
 * `POST /api/picker/browse`: opens the OS folder dialog (one at a time) and returns at once. A
 * new dialog waits until the last one's process has exited and a short pause has passed.
 */
export function openFolderDialog(context: PickerContext, lang: unknown): PickerBrowseResponse {
  const picker = context.picker;
  if (picker === undefined) throw new ApiError(500, "internal", "Internal error.");
  const browse = context.state.picker.browse;
  if (browse.controller !== null) {
    throw new ApiError(
      409,
      "dialog_open",
      "A folder dialog is already open. Finish or cancel it first.",
    );
  }
  if (browse.isProcessRunning || context.now() < browse.reopenAfter) {
    throw new ApiError(
      409,
      "dialog_closing",
      "The last folder window is still closing. Try again in a moment.",
    );
  }
  if (picker.folderDialog === undefined) {
    browse.response = { status: "unavailable", candidate: null, refusal: null };
    return browse.response;
  }
  const controller = new AbortController();
  browse.controller = controller;
  browse.isProcessRunning = true;
  browse.response = { status: "open", candidate: null, refusal: null };
  const prompt = lang === "ko" ? DIALOG_PROMPT.ko : DIALOG_PROMPT.en;
  const isCurrent = (): boolean => context.state.picker.browse.controller === controller;
  const dialogDone = picker.folderDialog({ prompt, signal: controller.signal });
  // The process has exited once the dialog settles (also after a cancel): then the pause starts.
  void dialogDone
    .then(
      () => undefined,
      () => undefined,
    )
    .finally(() => {
      browse.isProcessRunning = false;
      browse.reopenAfter = context.now() + DIALOG_REOPEN_PAUSE_MS;
    });
  void dialogDone
    .then(async (result) => {
      if (!isCurrent()) return;
      if (result.status !== "chosen") {
        browse.controller = null;
        browse.response = { status: result.status, candidate: null, refusal: null };
        return;
      }
      const absolute = expandPastedPath(result.path, picker.homeDir);
      const response =
        absolute === null ? refusal("bad_path") : await resolveFolderPath(context, absolute);
      if (!isCurrent()) return;
      browse.controller = null;
      browse.response =
        response.candidate !== null
          ? { status: "chosen", candidate: response.candidate, refusal: null }
          : { status: "refused", candidate: null, refusal: response.refusal };
    })
    .catch(() => {
      if (!isCurrent()) return;
      browse.controller = null;
      browse.response = { status: "unavailable", candidate: null, refusal: null };
    });
  return browse.response;
}

/** `GET /api/picker/browse`. */
export function getFolderDialog(context: PickerContext): PickerBrowseResponse {
  return context.state.picker.browse.response;
}

/** `POST /api/picker/browse/cancel`: closes the dialog (kills its process). A no-op when none. */
export function cancelFolderDialog(context: PickerContext): PickerBrowseResponse {
  const browse = context.state.picker.browse;
  browse.controller?.abort();
  browse.controller = null;
  browse.reopenAfter = Math.max(browse.reopenAfter, context.now() + DIALOG_REOPEN_PAUSE_MS);
  if (browse.response.status === "open") {
    browse.response = { status: "cancelled", candidate: null, refusal: null };
  }
  return browse.response;
}
