import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  COVERAGE_NOTE_CATALOG,
  COVERAGE_NOTE_CODES,
  WALK_STOPPED_PREFIX,
  catalogNoteText,
  coverageNote,
  coverageNoteText,
  prefixWalkStopped,
  type NoteParams,
} from "./coverage-notes.js";
import { compareScans } from "./compare-scans.js";
import { readScanResult } from "./read-result.js";
import type { Coverage, ScanResult } from "./contract.js";
import { SCHEMA_VERSION } from "./contract.js";

/** One valid parameter set per code. A new code without a sample fails the completeness test. */
const SAMPLES: Record<string, NoteParams> = {
  no_coverage: {},
  authorization_incomplete: {},
  blocked_by_gate: {},
  web_target_missing: {},
  web_scanner_unavailable: {},
  analyzer_failed: { scope: "history" },
  dependency_check_failed: {},
  history_config_excluded: { patterns: 2, set: "0123456789abcdef" },
  working_tree_files_checked: { count: 12 },
  walk_stopped_early: {},
  walk_stopped_entries: { visited: 5000, limit: 5000 },
  walk_stopped_time: { visited: 120 },
  large_files_skipped: { count: 3 },
  symlinks_not_followed: { count: 2, set: "ab12cd34ef56ab12" },
  directories_unreadable: { count: 1, set: "ab12cd34ef56ab12" },
  config_budget_exceeded: {},
  orm_unsupported: { library: "TypeORM" },
  language_files: { count: 12, language: "JavaScript", method: "js" },
  language_no_files: { language: "Go" },
  react_jsx_files: { count: 4 },
  react_no_jsx: {},
  heuristics_ran: {},
  heuristics_ran_partial: {},
  heuristics_not_run: {},
  python_other_categories: {},
  python_orm_unsupported: { library: "SQLAlchemy", count: 3 },
  python_process_unsupported: { library: "sh", count: 1 },
  history_no_commit: {},
  history_revision_not_found: { revision: "v1.2.3" },
  history_tracked_files: { count: 40, revision: "0123456789ab" },
  history_commits: { count: 9, revision: "0123456789ab" },
  web_authenticated_unavailable: {},
  web_pages_checked: { pages: 7 },
  dependencies_no_data_dir: { packages: 10, lockfiles: 1 },
  dependencies_data_missing: { ecosystem: "npm", packages: 10, lockfiles: 1 },
  dependencies_data_damaged: { ecosystem: "PyPI", packages: 10, lockfiles: 1 },
  dependencies_data_unreadable: { ecosystem: "Go" },
  dependencies_data_unverified: { ecosystem: "crates.io", packages: 10, lockfiles: 1 },
};

const HANGUL = /[가-힣]/;

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name === "dist") continue;
    const full = path.join(dir, name);
    if (statSync(full).isDirectory()) out.push(...sourceFiles(full));
    else if (/\.tsx?$/.test(name) && !/\.test\.tsx?$/.test(name)) out.push(full);
  }
  return out;
}

const PACKAGES = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

describe("coverage note catalog", () => {
  it("has a sample, an English text and a Korean text for every code", () => {
    expect([...COVERAGE_NOTE_CODES].sort()).toEqual(Object.keys(SAMPLES).sort());
    for (const code of COVERAGE_NOTE_CODES) {
      const params = SAMPLES[code] as NoteParams;
      const en = catalogNoteText(code, params, "en");
      const ko = catalogNoteText(code, params, "ko");
      expect(en, code).toEqual(expect.any(String));
      expect(ko, code).toEqual(expect.any(String));
      expect((en as string).length, code).toBeGreaterThan(5);
      expect(ko, code).toMatch(HANGUL);
      expect(en, code).not.toMatch(HANGUL);
    }
  });

  it("builds the English text the producers store from the catalog (byte-identical)", () => {
    expect(coverageNote("large_files_skipped", { count: 3 })).toEqual({
      note: "3 source file(s) over 1 MiB were skipped.",
      noteCode: "large_files_skipped",
      noteParams: { count: 3 },
    });
    expect(
      coverageNote("language_files", { count: 12, language: "JavaScript", method: "js" }).note,
    ).toBe(
      "12 JavaScript file(s); TypeScript compiler AST with intra-file, flow-insensitive taint tracking.",
    );
    expect(coverageNote("web_target_missing")).toEqual({
      note: "No confirmed local web target was selected.",
      noteCode: "web_target_missing",
    });
    expect(coverageNote("directories_unreadable", { count: 1, set: "ab" }).note).toBe(
      "1 directory could not be read, so files below it were not analyzed (set ab).",
    );
    expect(coverageNote("directories_unreadable", { count: 2, set: "ab" }).note).toBe(
      "2 directories could not be read, so files below them were not analyzed (set ab).",
    );
    expect(() => coverageNote("no_such_code")).toThrow();
    expect(() => coverageNote("large_files_skipped", { count: -1 })).toThrow();
  });

  it("is used by the producers: every emitted code is in the catalog and every code is emitted", () => {
    const emitted = new Set<string>();
    for (const file of sourceFiles(PACKAGES)) {
      if (file.endsWith(path.join("findings", "src", "coverage-notes.ts"))) continue;
      const text = readFileSync(file, "utf8");
      for (const match of text.matchAll(/coverageNote\(\s*"([a-z_]+)"/g)) {
        emitted.add(match[1] as string);
      }
      for (const code of COVERAGE_NOTE_CODES) {
        if (text.includes(`"${code}"`)) emitted.add(code);
      }
    }
    for (const code of emitted) expect(COVERAGE_NOTE_CODES, code).toContain(code);
    // `walk_stopped_early` is set by `prefixWalkStopped`, inside the catalog module.
    for (const code of COVERAGE_NOTE_CODES) {
      if (code !== "walk_stopped_early") expect([...emitted], code).toContain(code);
    }
  });

  it("falls back to the stored text for an unknown code, and for English", () => {
    const entry = { note: "Some English note.", noteCode: "never_heard_of_it" };
    expect(coverageNoteText(entry, "ko")).toBe("Some English note.");
    expect(coverageNoteText({ note: "Plain.", noteCode: "large_files_skipped" }, "en")).toBe(
      "Plain.",
    );
    expect(coverageNoteText({ note: "Old result." }, "ko")).toBe("Old result.");
    expect(coverageNoteText({ note: null, noteCode: "no_coverage" }, "ko")).toBeNull();
    for (const inherited of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
      expect(catalogNoteText(inherited, {}, "ko"), inherited).toBeNull();
    }
  });

  it("shows the Korean text for a known code with valid params", () => {
    expect(
      coverageNoteText(
        {
          note: "12 JavaScript file(s); 3 skipped",
          noteCode: "language_files",
          noteParams: { count: 12, language: "JavaScript", method: "js" },
        },
        "ko",
      ),
    ).toBe(
      "JavaScript 파일 12개. 방식: TypeScript 컴파일러 AST와 파일 안의 흐름 비민감 오염 추적.",
    );
  });

  it.each([
    ["markup in a label", "orm_unsupported", { library: "<img src=x onerror=alert(1)>" }],
    ["a quote in a label", "orm_unsupported", { library: 'a"b' }],
    ["an over-long label", "orm_unsupported", { library: "A".repeat(61) }],
    ["a control character", "orm_unsupported", { library: "Type\nORM" }],
    ["a bidi override", "orm_unsupported", { library: "Type‮ORM" }],
    ["a string where a count is expected", "large_files_skipped", { count: "3" }],
    ["a negative count", "large_files_skipped", { count: -3 }],
    ["a fractional count", "large_files_skipped", { count: 1.5 }],
    ["a huge count", "large_files_skipped", { count: 1e12 }],
    ["a non-hex set", "symlinks_not_followed", { count: 1, set: "<b>xx</b>" }],
    ["a value outside a fixed list", "analyzer_failed", { scope: "<script>" }],
    ["a missing param", "large_files_skipped", {}],
    ["an unknown param", "large_files_skipped", { count: 1, extra: "x" }],
    ["a bad walkStopped marker", "large_files_skipped", { count: 1, walkStopped: 2 }],
    ["params that are not an object", "large_files_skipped", "3"],
    ["params that are an array", "large_files_skipped", [3]],
  ])("falls back to the stored text for %s", (_name, code, params) => {
    const entry = { note: "STORED", noteCode: code, noteParams: params };
    expect(catalogNoteText(code, params, "ko")).toBeNull();
    expect(coverageNoteText(entry, "ko")).toBe("STORED");
  });

  it("never lets a param carry markup into the Korean text", () => {
    for (const code of COVERAGE_NOTE_CODES) {
      const params = { ...(SAMPLES[code] as NoteParams) };
      for (const key of Object.keys(params)) {
        const tampered = { ...params, [key]: `<script>alert(1)</script>${"x".repeat(5)}` };
        const text = catalogNoteText(code, tampered, "ko");
        expect(text === null || !/[<>]/.test(text), `${code}.${key}`).toBe(true);
      }
    }
  });

  it("prefixes a walk that stopped early without changing the stored English", () => {
    const withCode = coverageNote("large_files_skipped", { count: 3 }) as Coverage;
    const before = withCode.note as string;
    prefixWalkStopped(withCode);
    expect(withCode.note).toBe(`${WALK_STOPPED_PREFIX} ${before}`);
    expect(withCode.noteParams).toEqual({ count: 3, walkStopped: 1 });
    expect(coverageNoteText(withCode, "ko")).toBe(
      `${catalogNoteText("walk_stopped_early", {}, "ko")} 1 MiB를 넘는 소스 파일 3개를 건너뛰었습니다.`,
    );
    const empty: Pick<Coverage, "note" | "noteCode" | "noteParams"> = { note: null };
    prefixWalkStopped(empty);
    expect(empty).toEqual({ note: WALK_STOPPED_PREFIX, noteCode: "walk_stopped_early" });
    // A note with no code keeps English only.
    const plain: Pick<Coverage, "note" | "noteCode" | "noteParams"> = { note: "Free text." };
    prefixWalkStopped(plain);
    expect(plain).toEqual({ note: `${WALK_STOPPED_PREFIX} Free text.` });
  });

  it("has an English template for every code that matches a catalog entry shape", () => {
    for (const code of COVERAGE_NOTE_CODES) {
      expect(COVERAGE_NOTE_CATALOG[code]).toBeDefined();
    }
  });
});

function result(coverage: Coverage[]): ScanResult {
  return {
    schemaVersion: SCHEMA_VERSION,
    scanBasis: { mode: "authorized", authorization: "verified", reason: null },
    scanId: "s1",
    startedAt: "2026-10-31T00:00:00.000Z",
    finishedAt: "2026-10-31T00:00:01.000Z",
    tool: { name: "pgard", version: "0.1.0" },
    requestedScopes: ["code"],
    overallStatus: "completed",
    target: { repo: "o/n", revision: "abc", webOrigin: null },
    authorization: {
      decision: "allowed",
      checks: (
        [
          "repository",
          "github_identity",
          "owner_approval",
          "current_access",
          "contribution",
        ] as const
      ).map((id) => ({ id, status: "passed" as const, reason: "ok" })),
    },
    coverage,
    findings: [],
    advisoryDb: { version: null, updatedAt: null },
  } as ScanResult;
}

describe("schema 1.8 noteCode and noteParams", () => {
  it("is version 1.8", () => {
    expect(SCHEMA_VERSION).toBe("1.8");
  });

  it("round-trips a note code and its params through the reader", () => {
    const entry: Coverage = {
      area: "source:large-files",
      scope: "code",
      status: "partial",
      ruleIds: [],
      ...coverageNote("large_files_skipped", { count: 3 }),
    };
    const read = readScanResult(JSON.parse(JSON.stringify(result([entry]))));
    expect(read.ok && read.result.coverage[0]).toEqual(entry);
  });

  it("still reads and shows a 1.7 result without codes, with the stored text", () => {
    const old = JSON.parse(
      JSON.stringify(
        result([
          {
            area: "source:javascript",
            scope: "code",
            status: "completed",
            ruleIds: [],
            note: "12 JavaScript file(s); 3 skipped",
          },
        ]),
      ),
    );
    old.schemaVersion = "1.7";
    const read = readScanResult(old);
    expect(read.ok).toBe(true);
    if (!read.ok) return;
    expect(read.sourceVersion).toBe("1.7");
    const shown = read.result.coverage[0] as Coverage;
    expect(shown.noteCode).toBeUndefined();
    expect(coverageNoteText(shown, "ko")).toBe("12 JavaScript file(s); 3 skipped");
  });

  it("drops a malformed code or params instead of refusing the result", () => {
    const base = result([
      { area: "a", scope: "code", status: "completed", ruleIds: [], note: "Stored." },
    ]);
    const tampered = JSON.parse(JSON.stringify(base));
    tampered.coverage[0].noteCode = { evil: true };
    tampered.coverage[0].noteParams = { count: 1 };
    const readBadCode = readScanResult(tampered);
    expect(readBadCode.ok && readBadCode.result.coverage[0]).toEqual(base.coverage[0]);
    tampered.coverage[0].noteCode = "large_files_skipped";
    tampered.coverage[0].noteParams = { count: { nested: true } };
    const readBadParams = readScanResult(tampered);
    expect(readBadParams.ok && readBadParams.result.coverage[0]?.noteCode).toBe(
      "large_files_skipped",
    );
    expect(readBadParams.ok && readBadParams.result.coverage[0]?.noteParams).toBeUndefined();
    tampered.coverage[0].noteParams = { count: 1, big: "x".repeat(5000) };
    const readLong = readScanResult(tampered);
    expect(readLong.ok && readLong.result.coverage[0]?.noteParams).toBeUndefined();
  });
});

describe("notes never take part in identity or comparison (#449)", () => {
  it("compares two results the same whether or not their notes carry codes", () => {
    const plain: Coverage = {
      area: "source:large-files",
      scope: "code",
      status: "partial",
      ruleIds: [],
      note: "3 source file(s) over 1 MiB were skipped.",
    };
    const coded: Coverage = { ...plain, ...coverageNote("large_files_skipped", { count: 3 }) };
    expect(coded.note).toBe(plain.note);
    const a = compareScans(result([plain]), result([plain]));
    expect(compareScans(result([plain]), result([coded]))).toEqual(a);
    expect(compareScans(result([coded]), result([coded]))).toEqual(a);
  });
});
