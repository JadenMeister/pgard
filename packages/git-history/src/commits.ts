import { runGit as defaultRunGit, type GitRunner } from "./run-git.js";

const SHA_PATTERN = /^[0-9a-f]{40}$/;
const FIELD_SEPARATOR = "\u001f";
const MAX_LOG_ENTRIES = 2000;

/** Returns the `HEAD` commit SHA, or `null` if the repository has no valid commit. */
export async function readHeadRevision(
  projectRoot: string,
  runner: GitRunner = defaultRunGit,
): Promise<string | null> {
  try {
    const sha = (
      await runner(
        { subcommand: "rev-parse", flags: ["--verify", "--quiet"], operands: ["HEAD^{commit}"] },
        { cwd: projectRoot },
      )
    ).trim();
    return SHA_PATTERN.test(sha) ? sha : null;
  } catch {
    return null;
  }
}

/**
 * A local commit that may be the user's. Name and email are self-asserted by whoever made the
 * commit, so they are used only to order candidates — never as proof of authorship.
 */
export interface CommitCandidate {
  sha: string;
  authorName: string;
  authorEmail: string;
  committerName: string;
  committerEmail: string;
}

/** Lists recent local commits (all refs), newest first, bounded. */
export async function listCommitCandidates(
  projectRoot: string,
  runner: GitRunner = defaultRunGit,
  maxEntries = MAX_LOG_ENTRIES,
): Promise<CommitCandidate[]> {
  const limit = Math.max(1, Math.min(maxEntries, MAX_LOG_ENTRIES));
  const output = await runner(
    {
      // rev-list (plumbing) prints a "commit <sha>" header before each formatted line; those
      // header lines contain no field separator and are skipped below.
      subcommand: "rev-list",
      flags: [
        "--all",
        `--max-count=${limit}`,
        `--format=%H${FIELD_SEPARATOR}%an${FIELD_SEPARATOR}%ae${FIELD_SEPARATOR}%cn${FIELD_SEPARATOR}%ce`,
      ],
    },
    { cwd: projectRoot },
  );
  const seen = new Set<string>();
  const candidates: CommitCandidate[] = [];
  for (const line of output.split("\n")) {
    const [sha, authorName, authorEmail, committerName, committerEmail] =
      line.split(FIELD_SEPARATOR);
    if (!sha || !SHA_PATTERN.test(sha) || seen.has(sha)) {
      continue;
    }
    seen.add(sha);
    candidates.push({
      sha,
      authorName: authorName ?? "",
      authorEmail: authorEmail ?? "",
      committerName: committerName ?? "",
      committerEmail: committerEmail ?? "",
    });
  }
  return candidates;
}
