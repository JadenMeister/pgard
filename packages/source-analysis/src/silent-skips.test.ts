import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  MAX_NOTE_LENGTH,
  describeSkippedBuildDirectories,
  describeSkippedResourceXml,
  describeSpecialFiles,
  describeUnreadableEntries,
  scanSourceCode,
} from "./scan-source.js";

const roots: string[] = [];
const restore: string[] = [];
afterEach(() => {
  for (const directory of restore.splice(0)) chmodSync(directory, 0o755);
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function project(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-skip-")));
  roots.push(root);
  for (const [relative, content] of Object.entries(files)) {
    const target = path.join(root, relative);
    mkdirSync(path.dirname(target), { recursive: true });
    writeFileSync(target, content);
  }
  return root;
}

const SRC = "export const a = 1;\n";
const area = (result: Awaited<ReturnType<typeof scanSourceCode>>, name: string) =>
  result.coverage.find((item) => item.area === name);
// Assembled at run time so the source holds no secret-shaped literal.
const FAKE_KEY = ["sk", "live", "abcdefghijklmnopqrstuvwxyz0123"].join("_");
const HOSTILE = `dist/\u001b[31m\n${FAKE_KEY}`;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f]/;

describe("build output directories", () => {
  it("lists skipped build output as an informational area with a set fingerprint and a reason", async () => {
    const root = project({
      "src/a.ts": SRC,
      "dist/bundle.js": SRC,
      "packages/web/build/x.js": SRC,
      "packages/web/.next/y.js": SRC,
      "coverage/lcov.js": SRC,
      ".git/config": "x",
    });
    const entry = area(await scanSourceCode(root), "source:build-output");
    expect(entry).toMatchObject({ scope: "code", status: "completed", ruleIds: [] });
    expect(entry?.note).toMatch(
      /^4 build output directories skipped \(build output, not analyzed; set [0-9a-f]{8}\): "coverage\/", "dist\/", "packages\/web\/\.next\/", "packages\/web\/build\/"\./,
    );
    expect(entry?.note).toContain("Not configurable");
    expect(entry?.note).not.toContain(".git");
    expect((entry?.note ?? "").length).toBeLessThanOrEqual(MAX_NOTE_LENGTH);
  });

  it("is partial when no source was found anywhere, since the only source may live there", async () => {
    const root = project({ "build/server/main.go": "package main\n" });
    expect(area(await scanSourceCode(root), "source:build-output")?.status).toBe("partial");
  });

  it("adds no entry without such directories, and .d.ts files stay silent", async () => {
    const root = project({ "src/a.ts": SRC, "src/types.d.ts": "export {};\n" });
    const result = await scanSourceCode(root);
    for (const name of [
      "source:build-output",
      "source:xml-skipped",
      "source:unreadable-files",
      "source:special-files",
    ]) {
      expect(area(result, name), name).toBeUndefined();
    }
  });

  it("changes the note when the set changes at the same count", async () => {
    const first = await scanSourceCode(project({ "src/a.ts": SRC, "dist/x.js": SRC }));
    const second = await scanSourceCode(project({ "src/a.ts": SRC, "out/x.js": SRC }));
    expect(area(first, "source:build-output")?.note).not.toBe(
      area(second, "source:build-output")?.note,
    );
  });

  it("caps the list, counts the rest, and sanitises hostile names", () => {
    const many = Array.from({ length: 8 }, (_, index) => `d${7 - index}/dist`);
    expect(describeSkippedBuildDirectories(many)).toMatch(
      /^8 build output directories skipped \(build output, not analyzed; set [0-9a-f]{8}\): "d0\/dist\/", "d1\/dist\/", "d2\/dist\/", "d3\/dist\/", "d4\/dist\/" and 3 more\./,
    );
    expect(describeSkippedBuildDirectories(["dist"])).toMatch(/^1 build output directory skipped/);
    const long = Array.from({ length: 6 }, (_, i) => `${"a".repeat(200)}${i}/build`);
    const hostile = describeSkippedBuildDirectories([HOSTILE, ...long]);
    expect(hostile.length).toBeLessThanOrEqual(MAX_NOTE_LENGTH);
    expect(hostile).not.toMatch(CONTROL);
    expect(hostile).not.toContain(FAKE_KEY);
    expect(hostile).toMatch(/and \d+ more\./);
  });
});

describe("XML under res/ or target/", () => {
  it("counts it as skipped instead of dropping it", async () => {
    const root = project({
      "src/a.ts": SRC,
      "app/src/main/res/layout/main.xml": "<LinearLayout/>",
      "tools/target/out.xml": "<a/>",
      "config/mapper.xml": "<a/>",
    });
    const entry = area(await scanSourceCode(root), "source:xml-skipped");
    expect(entry).toMatchObject({ status: "completed", ruleIds: [] });
    expect(entry?.note).toMatch(
      /^2 XML files under res\/ or target\/ not checked for MyBatis mappers \(Android resources or build output, not analyzed; set [0-9a-f]{8}\): "app\/src\/main\/res\/layout\/main\.xml", "tools\/target\/out\.xml"\.$/,
    );
  });

  it("stays within the note limit with hostile names", () => {
    const note = describeSkippedResourceXml([
      `res/${HOSTILE}.xml`,
      ...Array.from({ length: 6 }, (_, i) => `${"b".repeat(150)}${i}/res/a.xml`),
    ]);
    expect(note.length).toBeLessThanOrEqual(MAX_NOTE_LENGTH);
    expect(note).not.toMatch(CONTROL);
  });
});

describe("unreadable and special files", () => {
  it.skipIf(process.getuid?.() === 0)("counts files whose lstat fails as partial", async () => {
    const root = project({ "src/a.ts": SRC, "locked/b.ts": SRC, "locked/c.xml": "<a/>" });
    const locked = path.join(root, "locked");
    chmodSync(locked, 0o644); // listable, not searchable: lstat of the entries fails with EACCES
    restore.push(locked);
    const entry = area(await scanSourceCode(root), "source:unreadable-files");
    expect(entry).toMatchObject({ status: "partial", ruleIds: [] });
    expect(entry?.note).toMatch(
      /^2 files could not be read \(permission error or removed during the scan, not analyzed; set [0-9a-f]{8}\): "locked\/b\.ts", "locked\/c\.xml"\.$/,
    );
  });

  it("counts FIFOs once in an informational note and never opens them", async () => {
    const root = project({ "src/a.ts": SRC });
    execFileSync("mkfifo", [path.join(root, "pipe")]);
    const entry = area(await scanSourceCode(root), "source:special-files");
    expect(entry).toMatchObject({ status: "completed", ruleIds: [] });
    expect(entry?.note).toMatch(
      /^1 special file skipped \(FIFO, socket, device or not a regular file, never opened; set [0-9a-f]{8}\): "pipe"\.$/,
    );
  });

  it("keeps both notes within the limit and sanitised", () => {
    const names = [HOSTILE, ...Array.from({ length: 7 }, (_, i) => `${"c".repeat(180)}${i}`)];
    for (const note of [describeUnreadableEntries(names), describeSpecialFiles(names)]) {
      expect(note.length).toBeLessThanOrEqual(MAX_NOTE_LENGTH);
      expect(note).not.toMatch(CONTROL);
      expect(note).not.toContain(FAKE_KEY);
    }
  });
});

describe("JVM XML in a Kotlin-only project", () => {
  const KOTLIN = "fun f() {}\n";
  const BIG_XML = `<mapper>${"<!-- pad -->".repeat(100_000)}</mapper>`;

  it("reports XML over 1 MiB even when there are no Java files", async () => {
    const root = project({ "src/main/kotlin/A.kt": KOTLIN, "src/main/resources/big.xml": BIG_XML });
    const entry = area(await scanSourceCode(root), "source:mybatis");
    expect(entry).toMatchObject({ status: "partial", ruleIds: [] });
    expect(entry?.note).toMatch(/1 XML file\(s\) were binary, unreadable or over 1 MiB/);
  });

  it("stays quiet for a project that is not JVM", async () => {
    const root = project({ "src/a.ts": SRC, "conf/big.xml": BIG_XML });
    expect(area(await scanSourceCode(root), "source:mybatis")).toBeUndefined();
  });
});
