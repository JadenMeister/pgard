import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import {
  compareVersions,
  decideUpdate,
  MIN_AGE_MS,
} from "../../packaging/homebrew/tap-workflow/next-version.mjs";
import { decideExisting } from "../../packaging/homebrew/tap-workflow/existing-pr.mjs";

// The workflow source lives here and runs in the tap repository. No YAML parser is a dependency
// of this repo, so the checks below read the file as text, line by line.
const dir = path.resolve(import.meta.dirname, "../../packaging/homebrew/tap-workflow");
const workflow = readFileSync(path.join(dir, "update-formula.yml"), "utf8");
const lines = workflow.split("\n");

/** Text of every `run:` body (inline or block scalar). */
function runBodies(): string[] {
  const bodies: string[] = [];
  for (let i = 0; i < lines.length; i += 1) {
    const match = /^(\s*)(?:- )?run:\s*(.*)$/.exec(lines[i] ?? "");
    if (!match) continue;
    const indent = (match[1] ?? "").length;
    const rest = match[2] ?? "";
    if (!rest.startsWith("|") && !rest.startsWith(">")) {
      bodies.push(rest);
      continue;
    }
    const block: string[] = [];
    for (let j = i + 1; j < lines.length; j += 1) {
      const line = lines[j] ?? "";
      if (line.trim() !== "" && line.length - line.trimStart().length <= indent) break;
      block.push(line);
    }
    bodies.push(block.join("\n"));
  }
  return bodies;
}

describe("tap workflow source", () => {
  it("has the expected triggers and no pull_request_target", () => {
    expect(workflow).toMatch(/^on:\n {2}schedule:/m);
    expect(workflow).toMatch(/^ {2}workflow_dispatch:/m);
    expect(workflow).not.toMatch(/pull_request_target/);
    expect(workflow).not.toMatch(/^ {2}pull_request:/m);
  });

  it("sets empty top-level permissions and a concurrency group", () => {
    expect(workflow).toMatch(/^permissions: \{\}$/m);
    expect(workflow).toMatch(
      /^concurrency:\n {2}group: update-formula\n {2}cancel-in-progress: false$/m,
    );
  });

  it("grants write access only to the update job (push, PR) and the report job (comment)", () => {
    const writes = lines.filter((line) => /: write\b/.test(line));
    expect(writes.map((line) => line.trim().split(" ")[0])).toEqual([
      "contents:",
      "pull-requests:",
      "pull-requests:",
    ]);
    const testJob = workflow.slice(
      workflow.indexOf("\n  test:"),
      workflow.indexOf("\n  # Comments the macOS"),
    );
    expect(testJob).toMatch(/permissions:\n {6}contents: read\n/);
    expect(testJob).not.toContain("write");
    const reportJob = workflow.slice(workflow.indexOf("\n  report:"));
    expect(reportJob).toMatch(/permissions:\n {6}pull-requests: write[^\n]*\n {4}steps:/);
    expect(reportJob).toContain("needs: [update, test]");
    expect(reportJob).toContain("needs.test.result");
  });

  it("pins every action to a 40-hex commit SHA with a version comment", () => {
    const uses = lines.filter((line) => /^\s*(?:- )?uses:/.test(line));
    expect(uses.length).toBeGreaterThan(0);
    for (const line of uses) {
      expect(line).toMatch(/uses: [\w.-]+\/[\w.-]+@[0-9a-f]{40} # v\d+/);
    }
  });

  it("uses no secret other than the built-in token", () => {
    const secrets = workflow.match(/secrets\.[A-Za-z0-9_]+/g) ?? [];
    expect(secrets).toEqual([]);
    expect(workflow).not.toMatch(/secrets\.(?!GITHUB_TOKEN)/);
  });

  it("never merges or enables auto-merge", () => {
    expect(workflow).not.toMatch(/auto-?merge/i);
    expect(workflow).not.toMatch(/gh pr merge/);
    expect(workflow).not.toMatch(/--merge|--squash|--rebase/);
  });

  it("keeps every ${{ }} expression out of run bodies", () => {
    const bodies = runBodies();
    expect(bodies.length).toBeGreaterThan(3);
    for (const body of bodies) {
      expect(body).not.toContain("${{");
      expect(body).not.toMatch(/github\.event\.inputs/);
    }
  });

  it("passes the input and registry-derived values through env and validates them", () => {
    expect(workflow).toMatch(/INPUT_VERSION: \$\{\{ inputs\.version \}\}/);
    expect(workflow).not.toMatch(/github\.event\.inputs/);
    expect(workflow).toContain("semver='^[0-9]+\\.[0-9]+\\.[0-9]+$'");
    const consumers = runBodies().filter((body) => body.includes("$VERSION"));
    expect(consumers.length).toBeGreaterThan(0);
    for (const body of consumers) expect(body).toContain("[0-9]+\\.[0-9]+\\.[0-9]+$");
  });

  it("does not persist the checkout token", () => {
    const checkouts = lines.filter((line) => line.includes("actions/checkout@"));
    const persist = lines.filter((line) => line.trim().startsWith("persist-credentials:"));
    expect(checkouts).toHaveLength(3);
    expect(persist).toHaveLength(3);
    for (const line of persist) expect(line).toContain("persist-credentials: false");
  });

  it("commits as github-actions[bot] and opens the PR with gh", () => {
    expect(workflow).toContain('git config user.name "github-actions[bot]"');
    expect(workflow).toContain('git commit -m "pgard $VERSION"');
    expect(workflow).toContain("update-pgard-$VERSION");
    expect(workflow).toContain("gh pr create");
  });

  it("runs the macOS checks in a second job that needs the first", () => {
    expect(workflow).toMatch(/needs: update/);
    expect(workflow).toMatch(/runs-on: macos-latest/);
    for (const command of [
      "brew audit --strict",
      "brew install --build-from-source",
      "brew test",
    ]) {
      expect(workflow).toContain(command);
    }
  });

  it("carries the scripts commit placeholder exactly once, as the ref of the pgard checkout", () => {
    const token = "PGARD_SCRIPTS_SHA_PLACEHOLDER";
    expect(token).toMatch(/^[A-Z_]+$/);
    expect(workflow.split(token)).toHaveLength(2);
    const index = lines.findIndex((line) => line.includes(token));
    expect(lines[index]?.trim()).toBe(`ref: ${token}`);
    expect(lines[index - 1]?.trim()).toBe("repository: JadenMeister/pgard");
    // The other `ref:`s are the tap's default branch and the pushed commit of the test job.
    expect(lines.filter((line) => /^\s*ref:/.test(line)).map((line) => line.trim())).toEqual([
      "ref: ${{ github.event.repository.default_branch }}",
      `ref: ${token}`,
      "ref: ${{ needs.update.outputs.sha }}",
    ]);
    expect(workflow).not.toContain("GITHUB_REF_NAME");
  });

  it("checks the ls-remote exit code instead of failing open", () => {
    expect(workflow).toContain(
      'git ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1 || rc=$?',
    );
    expect(workflow).toMatch(/2\) ;;\n\s+\*\) echo "git ls-remote failed[^\n]*exit 1 ;;/);
  });

  it("audits without --online and tests the pushed commit", () => {
    expect(workflow).toContain("brew audit --strict jadenmeister/pgard/pgard");
    expect(workflow).not.toContain("--online");
    expect(workflow).toContain('echo "sha=$(git rev-parse HEAD)"');
  });

  it("calls next-version.mjs and update-formula.sh from the pinned checkout", () => {
    expect(workflow).toContain("pgard-scripts/packaging/homebrew/tap-workflow/next-version.mjs");
    expect(workflow).toContain("pgard-scripts/packaging/homebrew/update-formula.sh");
    expect(workflow).toContain("--registry=https://registry.npmjs.org/");
  });
});

const day = MIN_AGE_MS;
const now = Date.parse("2026-11-17T12:00:00Z");
const old = new Date(now - 2 * day).toISOString();
const fresh = new Date(now - day / 2).toISOString();

describe("formula version extraction (the sed from the workflow)", () => {
  const match = /sed -nE '([^']+)' Formula\/pgard\.rb/.exec(workflow);
  const tmp = mkdtempSync(path.join(tmpdir(), "formula-sed-"));
  function versionOf(formula: string): string {
    const file = path.join(tmp, "pgard.rb");
    writeFileSync(file, formula);
    return spawnSync("sed", ["-nE", match?.[1] ?? "", file], { encoding: "utf8" }).stdout.trim();
  }
  afterAll(() => rmSync(tmp, { recursive: true, force: true }));

  it("is found in the workflow", () => {
    expect(match).not.toBeNull();
  });

  it("reads the version of the template formula", () => {
    const template = readFileSync(path.join(dir, "../pgard.rb"), "utf8");
    expect(versionOf(template)).toBe("0.1.0");
  });

  it("reads the version of a 0.2.0-style tap formula", () => {
    const formula = [
      "class Pgard < Formula",
      '  homepage "https://github.com/JadenMeister/pgard"',
      '  url "https://registry.npmjs.org/pgard/-/pgard-0.2.0.tgz"',
      `  sha256 "${"ab".repeat(32)}"`,
      '  license "MIT"',
      "end",
    ].join("\n");
    expect(versionOf(formula)).toBe("0.2.0");
  });

  it("reads nothing from a url that is not the registry tarball", () => {
    expect(versionOf('  url "https://example.com/pgard-0.9.0.tgz"\n')).toBe("");
  });
});

describe("existing-pr decideExisting", () => {
  it("proceeds when there is no branch and no PR", () => {
    expect(decideExisting({ branchExists: false, prs: [] })).toEqual({ found: false });
  });

  it("skips for an open or merged PR", () => {
    for (const state of ["OPEN", "MERGED"]) {
      expect(decideExisting({ branchExists: true, prs: [{ state }] })).toEqual({ found: true });
    }
  });

  it("fails closed for a branch without an open or merged PR", () => {
    expect(() => decideExisting({ branchExists: true, prs: [] })).toThrow(/delete the branch/);
    expect(() => decideExisting({ branchExists: true, prs: [{ state: "CLOSED" }] })).toThrow();
  });

  it("proceeds when only a closed PR is left and the branch is gone", () => {
    expect(decideExisting({ branchExists: false, prs: [{ state: "CLOSED" }] })).toEqual({
      found: false,
    });
  });

  it("rejects entries without a string state", () => {
    for (const prs of [[null], [1], [{}], [{ state: 1 }], ["OPEN"]]) {
      expect(() => decideExisting({ branchExists: false, prs })).toThrow(/string state/);
    }
  });

  it("rejects a malformed PR list", () => {
    expect(() => decideExisting({ branchExists: false, prs: null })).toThrow();
  });
});

describe("next-version decideUpdate", () => {
  it("rejects input that could inject an output line", () => {
    const evil = "1.0.0-x\nversion=9.9.9";
    expect(() => decideUpdate({ current: "0.2.0", latest: evil, time: {}, now })).toThrow();
    expect(() =>
      decideUpdate({ current: "0.2.0", latest: "0.3.0", requested: evil, time: {}, now }),
    ).toThrow(/characters/);
  });

  it("honours an explicit version when npm latest is a pre-release", () => {
    expect(
      decideUpdate({
        current: "0.2.0",
        latest: "0.4.0-rc.1",
        requested: "0.3.0",
        time: { "0.3.0": old },
        now,
      }).version,
    ).toBe("0.3.0");
  });

  it("proposes a newer version that is old enough", () => {
    expect(
      decideUpdate({ current: "0.2.0", latest: "0.3.0", time: { "0.3.0": old }, now }),
    ).toEqual({ version: "0.3.0", reason: "0.2.0 -> 0.3.0" });
  });

  it("compares numerically, not as text", () => {
    expect(compareVersions("0.10.0", "0.9.0")).toBe(1);
    expect(compareVersions("1.0.0", "0.99.99")).toBe(1);
    expect(compareVersions("0.2.0", "0.2.0")).toBe(0);
    expect(compareVersions("0.2.1", "0.3.0")).toBe(-1);
    expect(
      decideUpdate({ current: "0.9.0", latest: "0.10.0", time: { "0.10.0": old }, now }).version,
    ).toBe("0.10.0");
  });

  it("does nothing for an equal or older latest", () => {
    for (const latest of ["0.2.0", "0.1.9"]) {
      const result = decideUpdate({ current: "0.2.0", latest, time: { [latest]: old }, now });
      expect(result.version).toBeNull();
      expect(result.reason).toContain("not newer");
    }
  });

  it("ignores a pre-release", () => {
    const result = decideUpdate({
      current: "0.2.0",
      latest: "0.3.0-rc.1",
      time: { "0.3.0-rc.1": old },
      now,
    });
    expect(result.version).toBeNull();
    expect(result.reason).toContain("pre-release");
  });

  it("skips a version published less than 24 hours ago", () => {
    const result = decideUpdate({
      current: "0.2.0",
      latest: "0.3.0",
      time: { "0.3.0": fresh },
      now,
    });
    expect(result.version).toBeNull();
    expect(result.reason).toContain("24 hours");
    const exactly = new Date(now - day).toISOString();
    expect(
      decideUpdate({ current: "0.2.0", latest: "0.3.0", time: { "0.3.0": exactly }, now }).version,
    ).toBe("0.3.0");
  });

  it("uses the requested version instead of latest", () => {
    expect(
      decideUpdate({
        current: "0.2.0",
        latest: "0.4.0",
        requested: "0.3.0",
        time: { "0.3.0": old, "0.4.0": old },
        now,
      }).version,
    ).toBe("0.3.0");
  });

  it("rejects invalid input", () => {
    const time = { "0.3.0": old };
    for (const bad of ["", "v0.3.0", "0.3", "0.3.0\n", "0.3.0 && id", "../0.3.0", "latest"]) {
      expect(() => decideUpdate({ current: "0.2.0", latest: bad, time, now })).toThrow();
      expect(() => decideUpdate({ current: bad, latest: "0.3.0", time, now })).toThrow();
    }
    expect(() => decideUpdate({ current: "0.2.0", latest: "0.3.0", time: {}, now })).toThrow(
      /no publish time/,
    );
    expect(() => decideUpdate({ current: "0.2.0", latest: "0.3.0", time: null, now })).toThrow();
    expect(() =>
      decideUpdate({ current: "0.2.0", latest: "0.3.0", time, now: Number.NaN }),
    ).toThrow();
  });
});

describe("next-version CLI", () => {
  const script = path.join(dir, "next-version.mjs");

  function run(args: string[], time: unknown) {
    const tmp = mkdtempSync(path.join(tmpdir(), "next-version-"));
    try {
      const file = path.join(tmp, "time.json");
      writeFileSync(file, JSON.stringify(time));
      return spawnSync(process.execPath, [script, ...args, "--time-file", file], {
        encoding: "utf8",
      });
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  }

  it("prints GITHUB_OUTPUT lines for an update", () => {
    const result = run(
      [
        "--current",
        "0.2.0",
        "--latest",
        "0.3.0",
        "--requested",
        "",
        "--now",
        "2026-11-17T12:00:00Z",
      ],
      { "0.3.0": old },
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toBe("version=0.3.0\nreason=0.2.0 -> 0.3.0\n");
  });

  it("prints an empty version when there is nothing to do", () => {
    const result = run(
      [
        "--current",
        "0.3.0",
        "--latest",
        "0.3.0",
        "--requested",
        "",
        "--now",
        "2026-11-17T12:00:00Z",
      ],
      { "0.3.0": old },
    );
    expect(result.status).toBe(0);
    expect(result.stdout).toMatch(/^version=\nreason=/);
  });

  it("exits 2 and prints nothing on stdout for invalid input", () => {
    const result = run(
      [
        "--current",
        "0.2.0",
        "--latest",
        "0.3.0; id",
        "--requested",
        "",
        "--now",
        "2026-11-17T12:00:00Z",
      ],
      { "0.3.0": old },
    );
    expect(result.status).toBe(2);
    expect(result.stdout).toBe("");
    expect(result.stderr).toMatch(/version/);
  });
});
