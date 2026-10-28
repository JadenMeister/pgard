import { GitCommandError, runGit as defaultRunGit, type GitRunner } from "./run-git.js";

export interface GitHubRepositoryRef {
  owner: string;
  name: string;
}

export type GitHubRemoteResolution =
  | { isResolved: true; repo: GitHubRepositoryRef; remoteName: string }
  | { isResolved: false; reason: string };

const OWNER_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_PATTERN = /^[A-Za-z0-9._-]{1,100}$/;
const REMOTE_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._\/-]{0,99}$/;
const GITHUB_HOSTS = new Set(["github.com", "ssh.github.com"]);

function toRepoRef(owner: string, rawName: string): GitHubRepositoryRef | null {
  const name = rawName.endsWith(".git") ? rawName.slice(0, -4) : rawName;
  if (!OWNER_PATTERN.test(owner) || !REPO_PATTERN.test(name) || name === "." || name === "..") {
    return null;
  }
  return { owner, name };
}

function splitRepoPath(pathname: string): GitHubRepositoryRef | null {
  const trimmed = pathname.replace(/^\/+/, "").replace(/\/+$/, "");
  const parts = trimmed.split("/");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return null;
  }
  return toRepoRef(parts[0], parts[1]);
}

/**
 * Parses a remote URL that points at a repository on github.com. Returns `null` for any other
 * host, extra path segments, query strings or unrecognized syntax. Accepted forms:
 * `https://github.com/o/r(.git)`, `ssh://git@github.com/o/r.git`, `git@github.com:o/r.git`.
 */
export function parseGitHubRemoteUrl(url: string): GitHubRepositoryRef | null {
  const value = url.trim();
  if (value.length === 0 || value.length > 500 || /\s/.test(value)) {
    return null;
  }
  const scpLike = /^git@([A-Za-z0-9.-]+):([^/]+)\/([^/]+?)\/?$/.exec(value);
  if (scpLike) {
    const [, host, owner, name] = scpLike;
    if (!host || !owner || !name || !GITHUB_HOSTS.has(host.toLowerCase())) {
      return null;
    }
    return toRepoRef(owner, name);
  }
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (!["https:", "ssh:", "git:"].includes(parsed.protocol)) {
    return null;
  }
  if (!GITHUB_HOSTS.has(parsed.hostname.toLowerCase())) {
    return null;
  }
  if (parsed.search || parsed.hash) {
    return null;
  }
  if (parsed.protocol === "ssh:" && parsed.username !== "git") {
    return null;
  }
  // GitHub owner/repository names never contain percent-encoding; refuse it instead of decoding
  // (decoding can also throw on malformed sequences).
  if (parsed.pathname.includes("%")) {
    return null;
  }
  return splitRepoPath(parsed.pathname);
}

function sameRepo(a: GitHubRepositoryRef, b: GitHubRepositoryRef): boolean {
  return (
    a.owner.toLowerCase() === b.owner.toLowerCase() && a.name.toLowerCase() === b.name.toLowerCase()
  );
}

function lines(output: string): string[] {
  return output
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

const REWRITE_KEY_PATTERN = /^url\..*\.(?:insteadof|pushinsteadof)$/is;
const REWRITE_REASON =
  "The repository config rewrites remote URLs (url.*.insteadOf or url.*.pushInsteadOf), so its GitHub identity can't be confirmed; remove the rewrite and check again.";

interface ConfigEntry {
  key: string;
  value: string;
}

/**
 * Raw `remote.<name>.url`, `remote.<name>.pushurl` and URL rewrite settings from the effective
 * repository config (includes followed; system and global config are disabled by the runner).
 * `git remote get-url` is not used because it applies `url.<base>.insteadOf` and so can report
 * a different host than the one configured.
 */
async function readRawRemoteConfig(projectRoot: string, runner: GitRunner): Promise<ConfigEntry[]> {
  let output: string;
  try {
    output = await runner(
      {
        subcommand: "config",
        flags: ["--null", "--get-regexp"],
        operands: ["^(remote\\..*\\.(url|pushurl)|url\\..*\\.(insteadof|pushinsteadof))$"],
      },
      { cwd: projectRoot },
    );
  } catch (error) {
    // Exit code 1 means no key matched; an unrelated failure must not read as "no rewrites".
    if (error instanceof GitCommandError && error.exitCode === 1) return [];
    throw error;
  }
  const entries: ConfigEntry[] = [];
  for (const record of output.split("\0")) {
    if (record.length === 0) continue;
    const newline = record.indexOf("\n");
    entries.push(
      newline === -1
        ? { key: record, value: "" }
        : { key: record.slice(0, newline), value: record.slice(newline + 1) },
    );
  }
  return entries;
}

function collectRemoteUrls(entries: readonly ConfigEntry[]): Map<string, string[]> {
  const urls = new Map<string, string[]>();
  for (const { key, value } of entries) {
    const match = /^remote\.(.+)\.(?:url|pushurl)$/is.exec(key);
    if (!match?.[1]) continue;
    const list = urls.get(match[1]) ?? [];
    list.push(value.trim());
    urls.set(match[1], list);
  }
  return urls;
}

/**
 * Resolves the single GitHub repository this checkout belongs to. Every fetch and push URL of
 * every remote must parse as the same github.com repository; any other host, an unparsable
 * URL, or remotes pointing at different repositories is rejected. Reasons never echo URLs,
 * which may embed credentials.
 */
export async function readGitHubRemote(
  projectRoot: string,
  runner: GitRunner = defaultRunGit,
): Promise<GitHubRemoteResolution> {
  let remoteNames: string[];
  try {
    remoteNames = lines(await runner({ subcommand: "remote" }, { cwd: projectRoot }));
  } catch {
    return { isResolved: false, reason: "Could not list Git remotes." };
  }
  if (remoteNames.length === 0) {
    return {
      isResolved: false,
      reason: "The repository has no Git remote; a github.com remote is required.",
    };
  }

  let rawUrls: Map<string, string[]>;
  try {
    const entries = await readRawRemoteConfig(projectRoot, runner);
    if (entries.some(({ key }) => REWRITE_KEY_PATTERN.test(key))) {
      return { isResolved: false, reason: REWRITE_REASON };
    }
    rawUrls = collectRemoteUrls(entries);
  } catch {
    return {
      isResolved: false,
      reason: "Could not read the Git remote URLs from the repository config.",
    };
  }

  let resolved: GitHubRepositoryRef | null = null;
  for (const remoteName of remoteNames) {
    if (!REMOTE_NAME_PATTERN.test(remoteName)) {
      return { isResolved: false, reason: "A Git remote has an unsupported name." };
    }
    const urls = rawUrls.get(remoteName) ?? [];
    if (urls.length === 0) {
      return { isResolved: false, reason: `Remote "${remoteName}" has no URL.` };
    }
    for (const url of urls) {
      const repo = parseGitHubRemoteUrl(url);
      if (repo === null) {
        return {
          isResolved: false,
          reason: `Remote "${remoteName}" is not a recognizable github.com repository URL; only github.com remotes are supported.`,
        };
      }
      if (resolved !== null && !sameRepo(resolved, repo)) {
        return {
          isResolved: false,
          reason:
            "Git remotes point to different GitHub repositories; the target repository is ambiguous.",
        };
      }
      resolved ??= repo;
    }
  }
  if (resolved === null) {
    return { isResolved: false, reason: "No github.com remote was found." };
  }
  const remoteName = remoteNames.includes("origin") ? "origin" : (remoteNames[0] ?? "origin");
  return { isResolved: true, repo: resolved, remoteName };
}
