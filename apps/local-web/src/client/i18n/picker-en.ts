/**
 * English texts of the project picker (`pgard web`). Kept in their own file so the main catalog
 * only gains one line; `ko.ts` takes the Korean twin from `picker-ko.ts`. The shape is checked
 * the same way: the Korean file is typed as `PickerMessages`, derived from this object.
 */
const HINT = "Type or drop only the folder's own name, not a path.";

export const pickerEn = {
  title: "Choose a project",
  lead: "Drop a project folder on the page or type its name. PGARD searches the folders you allowed in the terminal, shows the real path and the GitHub remote, and asks you to confirm. Nothing is scanned yet.",
  dropTitle: "Drop a project folder here",
  dropHint: "Only its name is used; nothing is uploaded.",
  dropActive: "Release to search for this folder",
  dropLabel: "Drop zone for a project folder",
  searchLabel: "Or type the folder's name",
  searchPlaceholder: "for example: shop",
  searchButton: "Search",
  cancelSearch: "Cancel search",
  searching: (visited: number): string =>
    visited === 0 ? "Searching..." : `Searching... ${visited} entries checked`,
  nameProblem: "That is not a folder name:",
  nameHint: HINT,
  nameReasons: {
    empty: "it is empty.",
    too_short: "it must be 2 or more characters.",
    too_long: "it is longer than 255 characters.",
    slash: "it contains a `/` or `\\`.",
    control: "it contains a control or direction-changing character.",
    dot: "`.` and `..` are not folder names.",
    malformed: "it is not valid text.",
    not_text: "it must be text.",
  },
  nameExample: "Type only the folder's own name, for example `shop`, not a path.",
  droppedFile: "Drop a folder, not a file.",
  droppedFileFix: "Drop the project's folder.",
  droppedNothing: "Nothing that looks like a folder was dropped.",
  noMatch: (name: string): string =>
    `No Git repository named "${name}" was found under the search folders.`,
  noMatchFix: "Check the name, or add its parent folder in the terminal:",
  searchedRoots: "Search folders",
  rootToggle: (label: string): string => `Search ${label} in this session`,
  noRoots: "No search folder is switched on. Switch one on above, or add a folder in the terminal.",
  copy: "Copy",
  copied: "Copied",
  partial: (seconds: number | null, by: "time" | "entries" | "candidates" | null): string => {
    if (by === "candidates") return "The search stopped at the limit of 20 matches.";
    if (by === "entries") return "The search stopped at the size limit.";
    return `The search stopped after ${seconds === null ? "its time limit" : `${seconds} s`}.`;
  },
  partialFix:
    "Type more of the name, or narrow the search folders in the terminal (`pgard web scope remove <folder>`).",
  uninspectedNote: (count: number): string =>
    `${count} folder${count === 1 ? " was" : "s were"} found but not checked in time; they are listed as not checked.`,
  several: "Several folders match. Choose by path and tag, not by name.",
  results: "Matches",
  choose: "Choose",
  collisionTag: (tag: string): string => `Tag ${tag}`,
  sourceScope: "Search folder",
  sourceRecent: "Recent",
  remoteLabel: "GitHub repository",
  noRemote: "no github.com remote",
  pathLabel: "Real path",
  escapedPathLabel: "Path with non-printable characters escaped",
  blockedTitle: "Cannot be selected",
  whyLabel: "Why",
  fixLabel: "What to do",
  failingPaths: "Folders and files to change",
  confirmTitle: "Check that this is the right project",
  confirmPath: "This is the folder PGARD will read.",
  confirmRemote: (repo: string): string => `The remote must be github.com/${repo}.`,
  confirmNext:
    "Next, PGARD checks that you are allowed to scan it. Nothing is scanned or sent anywhere yet.",
  confirmButton: "Confirm this project",
  confirming: "Checking the folder again...",
  back: "Back",
  recentTitle: "Recent projects",
  recentEmpty: "No recent projects yet.",
  recentValidating: "Checking recent projects...",
  recentIgnored:
    "The recent list could not be read (damaged or from a newer PGARD). It is ignored. Delete web/recent-projects.json in the PGARD data folder, or ignore this.",
  recentRemove: "Remove from recent",
  recentRemoveLabel: (name: string): string => `Remove ${name} from recent projects`,
  recentOffNote: "The recent list is off for this session (--no-store).",
  blocked: {
    not_a_git_root: {
      reason: "This folder is not a Git repository, or it is not the repository's top folder.",
      fix: "Pick the repository's top folder.",
    },
    no_commit_history: {
      reason: "The repository has no commits.",
      fix: "Make a first commit, then search again.",
    },
    isolation_failed: {
      reason:
        "The repository uses alternates, grafts or replace refs, so its history is not self-contained.",
      fix: "Use a normal clone.",
    },
    no_remote: {
      reason: "No remote points to github.com.",
      fix: "Run `git remote -v`, set one github.com remote, then search again.",
    },
    remote_not_github: {
      reason: "A remote of this repository does not point to github.com.",
      fix: "PGARD scans only github.com repositories you are authorized for.",
    },
    remote_ambiguous: {
      reason: "The remotes point to different repositories, or rewrite their URLs.",
      fix: "Run `git remote -v`, keep one github.com repository, then search again.",
    },
    remote_unreadable: {
      reason: "The remotes of this repository could not be read.",
      fix: "Run `git remote -v` in the folder, fix what it reports, then search again.",
    },
    not_owned_by_you: {
      reason: "This folder, or a folder above it, belongs to another user.",
      fix: "Clone it into your own folder.",
    },
    group_or_world_writable: {
      reason: "This folder, a folder above it, or its .git can be changed by other users.",
      fix: "Run this one command. It lists every folder and file that must change. On systems where each user has a private group, many folders are group-writable by default, so several may be listed: PGARD blocks them anyway because it cannot tell a private group from a shared one.",
    },
    gitfile_unsupported: {
      reason:
        "This project uses a linked worktree, a submodule or a .git pointer file. These are not supported yet.",
      fix: "Open the main clone of the repository instead.",
    },
    git_dir_unsupported: {
      reason: "This repository keeps its Git data outside the project folder.",
      fix: "Use a normal clone.",
    },
    outside_scope: {
      reason: "This recent project is outside the current search folders.",
      fix: "Add its folder in the terminal, or remove it from the recent list.",
    },
    unsafe_display: {
      reason: "The path contains characters that cannot be shown safely.",
      fix: "Rename the folder, or pick another one.",
    },
    not_inspected: {
      reason: "The search ran out of time before this folder was checked.",
      fix: "Type more of the name, or narrow the search folders in the terminal.",
    },
    unreadable: {
      reason: "This folder could not be read in time.",
      fix: "Check that the folder is readable and not on a slow or disconnected drive, then search again.",
    },
  },
  errors: {
    bad_name: HINT,
    bad_source: "The search could not be started. Reload the page.",
    search_too_soon: "Wait a second between searches.",
    inspector_busy:
      "Earlier searches are still stuck in the operating system (often a slow or disconnected network folder). Wait, or remove that folder from the search folders with `pgard web scope remove <folder>`.",
    candidate_changed:
      "The folder changed since you looked at it. Nothing was selected. Search again.",
    candidate_expired: "The confirmation expired. Nothing was selected. Search again.",
    candidate_blocked: "This folder cannot be selected.",
    unknown_candidate: "That folder is not known any more. Search again.",
    unknown_search: "That search is not known any more. Search again.",
    project_changed:
      "The project changed while this was running; the result was discarded. Run the action again.",
    scan_running: "A scan is running. Cancel it first, then change the project.",
    auth_running:
      "An authorization check is running. Cancel the check first, then change the project.",
    unreadable: "The folder could not be read in time. Nothing was started. Try again.",
    no_project: "Choose a project first.",
    fixed_project:
      "This dashboard was started for one project. To pick another, start `pgard web`.",
    generic: "The request failed. Try again.",
  },
  project: {
    label: "Project",
    change: "Change project",
    changeBlockedScan: "A scan is running. Cancel it first.",
    changeBlockedAuth: "A check is running. Cancel the check first.",
    cancelCheck: "Cancel check",
    cancelCheckHint: "Stops the running check, including a wait for the GitHub sign-in.",
    stale: "The project was changed in another window. This view is out of date.",
    reload: "Reload the state",
  },
} as const;

/** The shape both languages must have (`picker-ko.ts` is typed with it). */
export type PickerMessages = Widen<typeof pickerEn>;

type Widen<T> = T extends string
  ? string
  : T extends (...args: infer A) => infer R
    ? (...args: A) => R
    : { [K in keyof T]: Widen<T[K]> };
