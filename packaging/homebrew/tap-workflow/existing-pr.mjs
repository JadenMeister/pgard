#!/usr/bin/env node
// Decides what the tap workflow does when it finds (or does not find) work already done for a version.
//   node existing-pr.mjs --branch-exists true|false --prs-file prs.json
// prs.json is the output of `gh pr list --state all --head <branch> --json state`.
// Prints `found=true` (an OPEN or MERGED PR exists: nothing to do) or `found=false` (proceed).
// Fail-closed: a branch with no OPEN or MERGED PR (a push whose PR was never created, or a PR that
// was closed) exits 1 so the run is red; delete the branch to retry.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

/**
 * @param {{ branchExists: boolean, prs: unknown }} input
 * @returns {{ found: boolean }}
 */
export function decideExisting({ branchExists, prs }) {
  if (!Array.isArray(prs)) throw new Error("the PR list is not an array");
  for (const pr of prs) {
    if (!pr || typeof pr !== "object" || typeof pr.state !== "string") {
      throw new Error("the PR list has an entry without a string state");
    }
  }
  const states = prs.map((pr) => pr.state);
  if (states.some((state) => state === "OPEN" || state === "MERGED")) return { found: true };
  if (branchExists) {
    throw new Error(
      "the branch exists but has no open or merged PR (the PR was never created or was closed); delete the branch to retry",
    );
  }
  return { found: false };
}

function main() {
  const argv = process.argv.slice(2);
  const args = {};
  for (let i = 0; i < argv.length; i += 2) args[argv[i]?.replace(/^--/, "") ?? ""] = argv[i + 1];
  if (args["branch-exists"] !== "true" && args["branch-exists"] !== "false") {
    throw new Error("--branch-exists must be true or false");
  }
  if (!args["prs-file"]) throw new Error("--prs-file is required");
  const result = decideExisting({
    branchExists: args["branch-exists"] === "true",
    prs: JSON.parse(readFileSync(args["prs-file"], "utf8")),
  });
  process.stdout.write(`found=${result.found}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exit(1);
  }
}
