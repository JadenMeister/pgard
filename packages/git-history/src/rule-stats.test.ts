import { afterEach, describe, expect, it } from "vitest";
import { scanGitHistory } from "./scan-history.js";
import { createGitFixture, type GitFixture } from "./test-support/git-fixture.js";

// Assembled at runtime so nothing secret-looking is committed to this repo.
const REMOVED = ["ghp", "_", "R3mOv3dT0k3n", "AbCdEfGhIjKl", "MnOpQrStUvWxYz"].join("");

let fixture: GitFixture | null = null;
afterEach(() => {
  fixture?.cleanup();
  fixture = null;
});

type Output = Awaited<ReturnType<typeof scanGitHistory>>;
const statFor = (output: Output, area: string, ruleId: string) =>
  output.ruleStats?.find((stat) => stat.area === area && stat.ruleId === ruleId);

describe("scanGitHistory rule stats", () => {
  it("counts tracked files, commits and blobs that were really read, and findings per area", async () => {
    fixture = createGitFixture();
    fixture.commit({
      files: { "src/a.ts": `export const t = "${REMOVED}";\n`, "README.md": "one" },
    });
    fixture.commit({ files: { "src/a.ts": "export const t = process.env.T;\n", ".env": "A=1\n" } });
    fixture.commit({ files: { "README.md": "three" } });
    const output = await scanGitHistory(fixture.root);

    // Three files are tracked at HEAD (README.md, src/a.ts, .env); all were read as text.
    expect(statFor(output, "history:tracked-files", "PG-SECRET-001")).toMatchObject({
      scope: "history",
      status: "completed",
      targets: [{ unit: "files", examined: 3, reason: null }],
      findings: 1,
    });
    expect(statFor(output, "history:tracked-files", "PG-SECRET-002")).toMatchObject({
      targets: [{ unit: "files", examined: 3 }],
      findings: 0,
    });
    expect(statFor(output, "history:tracked-files", "PG-HYGIENE-001")?.findings).toBe(0);
    // Three commits; the removed token lives in a blob that is not at HEAD.
    expect(statFor(output, "history:commits", "PG-SECRET-003")).toMatchObject({
      status: "completed",
      targets: [
        { unit: "commits", examined: 3, reason: null },
        { unit: "blobs", reason: null },
      ],
      findings: 1,
    });
    const blobs = statFor(output, "history:commits", "PG-SECRET-003")?.targets[1]?.examined;
    expect(blobs).toBeGreaterThanOrEqual(1);
    // The environment file added in history was reported where it is tracked, not in commits.
    expect(statFor(output, "history:commits", "PG-SECRET-001")?.findings).toBe(0);
  });

  it("limits the commit count to the commits that were scanned", async () => {
    fixture = createGitFixture();
    for (let i = 0; i < 5; i += 1) fixture.commit({ files: { "README.md": `v${i}` } });
    const output = await scanGitHistory(fixture.root, { maxCommits: 2 });
    const stat = statFor(output, "history:commits", "PG-SECRET-003");
    expect(stat?.status).toBe("partial");
    expect(stat?.targets[0]).toMatchObject({ unit: "commits", examined: 2 });
  });

  it("has a row for each listed rule of a completed or partial area, and none when nothing ran", async () => {
    fixture = createGitFixture();
    fixture.commit({ files: { "README.md": "x" } });
    const output = await scanGitHistory(fixture.root);
    const expected = output.coverage
      .filter((entry) => entry.status !== "not_tested")
      .flatMap((entry) => entry.ruleIds.map((ruleId) => `${entry.area}|${ruleId}`))
      .sort();
    expect(output.ruleStats?.map((stat) => `${stat.area}|${stat.ruleId}`).sort()).toEqual(expected);

    const empty = createGitFixture();
    try {
      const none = await scanGitHistory(empty.root);
      expect(none.coverage.every((entry) => entry.status === "not_tested")).toBe(true);
      expect(none.ruleStats).toEqual([]);
    } finally {
      empty.cleanup();
    }
  });
});
