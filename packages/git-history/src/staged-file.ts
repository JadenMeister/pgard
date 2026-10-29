import { runGit as defaultRunGit, type GitRunner } from "./run-git.js";
import { decodeGitPath } from "./scan-history.js";

export type StagedFileRead =
  { state: "absent" } | { state: "ok"; text: string } | { state: "unreadable"; reason: string };

export interface StagedFileOptions {
  runner?: GitRunner;
  signal?: AbortSignal;
  /** The index to read (`GIT_INDEX_FILE` of a hook), already checked by the caller. */
  indexFile?: string;
  /** Largest file read. Default 64 KiB (the size limit of `pgard.config.json`). */
  maxBytes?: number;
}

/**
 * One small staged text file (for example `pgard.config.json`), read from the index like the
 * rest of a pre-commit check, so the version that is about to be committed is the one that
 * counts. `absent` means the index has no such path (an untracked file in the working tree is
 * not read). A link, a conflict entry, a file over `maxBytes` or one that is not valid UTF-8 is
 * `unreadable`, with a reason.
 */
export async function readStagedTextFile(
  projectRoot: string,
  relativePath: string,
  options: StagedFileOptions = {},
): Promise<StagedFileRead> {
  const runner = options.runner ?? defaultRunGit;
  const maxBytes = options.maxBytes ?? 64 * 1024;
  const common = {
    cwd: projectRoot,
    ...(options.signal ? { signal: options.signal } : {}),
  };
  try {
    const listed = await runner(
      { subcommand: "ls-files", flags: ["-s", "-z", "--full-name"], paths: [relativePath] },
      {
        ...common,
        encoding: "latin1",
        maxBuffer: 1024 * 1024,
        ...(options.indexFile ? { indexFile: options.indexFile } : {}),
      },
    );
    let found: { mode: string; sha: string; stage: number } | undefined;
    for (const record of listed.split("\0")) {
      const match = /^(\d{6}) ([0-9a-f]{40}) ([0-3])\t([\s\S]+)$/.exec(record);
      if (!match?.[1] || !match[2] || !match[3] || !match[4]) continue;
      if (decodeGitPath(match[4]) !== relativePath) continue;
      const entry = { mode: match[1], sha: match[2], stage: Number(match[3]) };
      if (found === undefined || entry.stage === 0) found = entry;
    }
    if (found === undefined) return { state: "absent" };
    if (found.stage !== 0) {
      return { state: "unreadable", reason: "it has an unresolved merge conflict" };
    }
    if (found.mode !== "100644" && found.mode !== "100755") {
      return { state: "unreadable", reason: "it is not a regular file" };
    }
    const size = (
      await runner({ subcommand: "cat-file", flags: ["-s"], operands: [found.sha] }, common)
    ).trim();
    if (!/^\d+$/.test(size) || Number(size) > maxBytes) {
      return { state: "unreadable", reason: `it is larger than ${maxBytes} bytes` };
    }
    const raw = await runner(
      { subcommand: "cat-file", flags: ["--batch"] },
      { ...common, input: `${found.sha}\n`, encoding: "latin1", maxBuffer: maxBytes + 1024 },
    );
    const headerEnd = raw.indexOf("\n");
    const header = /^[0-9a-f]{40} blob (\d+)$/.exec(raw.slice(0, headerEnd));
    if (headerEnd === -1 || !header?.[1]) {
      return { state: "unreadable", reason: "it could not be read" };
    }
    const body = Buffer.from(raw.slice(headerEnd + 1, headerEnd + 1 + Number(header[1])), "latin1");
    try {
      return { state: "ok", text: new TextDecoder("utf-8", { fatal: true }).decode(body) };
    } catch {
      return { state: "unreadable", reason: "it is not valid UTF-8 text" };
    }
  } catch (error) {
    if (options.signal?.aborted === true) throw error;
    return { state: "unreadable", reason: "it could not be read from the index" };
  }
}
