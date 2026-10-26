import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ANALYZER_HASH } from "./analyzer-hash.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

describe("analyzer hash", () => {
  it("is a SHA-256", () => {
    expect(ANALYZER_HASH).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is up to date with the analyzer sources (run `node scripts/analyzer-hash.mjs`)", () => {
    // Stored per-file results are reused only while this hash is unchanged, so editing an
    // analyzer, finding factory, redaction or fingerprint must change it. `npm run build`
    // regenerates it; this fails when a source changed and the file was not regenerated.
    const checked = spawnSync(process.execPath, ["scripts/analyzer-hash.mjs", "--check"], {
      cwd: root,
      encoding: "utf8",
    });
    expect(checked.stderr).toBe("");
    expect(checked.status).toBe(0);
  });
});
