import type { UpdateOutcome } from "@pgard/dependencies";
import { describe, expect, it } from "vitest";
import { main } from "../app.js";
import { parseCommandLine } from "../options.js";
import { createTestDeps, createTestIo } from "../test-support.js";

const noInterrupts = { on: () => undefined, off: () => undefined } as never;

const okOutcome = (ecosystem: "npm" | "Go"): UpdateOutcome => ({
  ecosystem,
  ok: true,
  downloadMs: 2500,
  indexMs: 900,
  meta: {
    schema: 1,
    ecosystem,
    sourceUrl: `https://osv-vulnerabilities.storage.googleapis.com/${ecosystem}/all.zip`,
    fetchedAt: "2026-10-26T00:00:00.000Z",
    archive: { bytes: 5 * 1024 * 1024, sha256: "a".repeat(64), lastModified: null, etag: null },
    counts: { entries: 12, advisories: 10, malware: 2, withdrawn: 0, skipped: 0 },
    modifiedRange: { min: "2020-01-01T00:00:00Z", max: "2026-10-25T00:00:00Z" },
    files: {},
  },
});

describe("pgard advisories update", () => {
  it("parses only the update subcommand without options", () => {
    expect(parseCommandLine(["advisories", "update"])).toEqual({ kind: "advisories-update" });
    expect(() => parseCommandLine(["advisories"])).toThrow(/Missing subcommand/);
    expect(() => parseCommandLine(["advisories", "sync"])).toThrow(/Unknown subcommand/);
    expect(() => parseCommandLine(["advisories", "update", "left-pad"])).toThrow(
      /Unexpected argument/,
    );
    expect(() => parseCommandLine(["advisories", "update", "--port", "1"])).toThrow(
      /not available/,
    );
  });

  it("downloads, prints sizes and counts, and exits 0", async () => {
    const captured = createTestIo();
    const calls: unknown[] = [];
    const code = await main(["advisories", "update"], captured.io, {
      deps: createTestDeps({
        updateAdvisories: (async (options: unknown) => {
          calls.push(options);
          return [okOutcome("npm"), okOutcome("Go")];
        }) as never,
      }),
      interrupts: noInterrupts,
    });
    expect(code).toBe(0);
    const stdout = captured.stdout();
    expect(stdout).toContain("nothing is uploaded; no package names are sent");
    expect(stdout).toContain("npm: 10 advisories + 2 malware (MAL-) records");
    expect(stdout).toContain("downloaded 5.0 MiB in 2.5 s");
    expect(calls).toHaveLength(1);
  });

  it("exits 4 and says the old data is unchanged when an ecosystem fails", async () => {
    const captured = createTestIo();
    const code = await main(["advisories", "update"], captured.io, {
      deps: createTestDeps({
        updateAdvisories: (async () => [
          okOutcome("npm"),
          { ecosystem: "Go", ok: false, error: "An entry failed its checksum." },
        ]) as never,
      }),
      interrupts: noInterrupts,
    });
    expect(code).toBe(4);
    expect(captured.stdout()).toContain(
      "[fail] Go: An entry failed its checksum. The previous data (if any) is unchanged.",
    );
  });

  it("is never run by a scan or doctor", async () => {
    const captured = createTestIo();
    const deps = createTestDeps(); // updateAdvisories throws if called
    expect(await main(["doctor"], captured.io, { deps, interrupts: noInterrupts })).toBe(0);
  });

  it("refuses with a clear message when there is no home directory", async () => {
    const captured = createTestIo();
    const code = await main(["advisories", "update"], captured.io, {
      deps: createTestDeps({ appDataDir: null }),
      interrupts: noInterrupts,
    });
    expect(code).toBe(4);
    expect(captured.stderr()).toContain("No home directory was found");
    expect(captured.stderr()).toContain("Nothing was downloaded");
  });
});
