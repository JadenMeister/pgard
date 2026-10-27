import { execFileSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import type { ProjectConfig } from "@pgard/findings";
import { afterEach, describe, expect, it } from "vitest";
import {
  MAX_NOTE_LENGTH,
  describeSkippedBuildDirectories,
  describeSkippedResourceXml,
  describeSpecialFiles,
  describeUnreadableEntries,
  scanSourceCode,
} from "./scan-source.js";
import { isUnderJvmSourceRoot } from "@pgard/findings";
import { MAX_FILES } from "./walk.js";

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
const JAVA = `import java.sql.*;
import javax.servlet.http.*;
class Foo {
  void f(Statement st, HttpServletRequest r) throws Exception {
    st.executeQuery("SELECT * FROM t WHERE a = " + r.getParameter("a"));
  }
}
`;
const area = (result: Awaited<ReturnType<typeof scanSourceCode>>, name: string) =>
  result.coverage.find((item) => item.area === name);
// Assembled at run time so the source holds no secret-shaped literal.
const FAKE_KEY = ["sk", "live", "abcdefghijklmnopqrstuvwxyz0123"].join("_");
const AWS_KEY = `AKIA${"ABCDEFGHIJKLMNOP"}`;
const HOSTILE = `dist/\u001b[31m\n${FAKE_KEY}`;
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f]/;
const noteOf = (
  paths: string[],
  extra: Partial<Parameters<typeof describeSkippedBuildDirectories>[0]> = {},
) => describeSkippedBuildDirectories({ paths, noSourceElsewhere: false, ...extra });

const VULN_TS =
  'import { Pool } from "pg";\nconst pool = new Pool();\nexport const q = (req) => pool.query(`SELECT * FROM t WHERE id = ${req.query.id}`);\n';

describe("directories skipped by name", () => {
  it("lists them as an informational area with a set fingerprint and a reason", async () => {
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
      /^4 directories skipped by name \(dist, build, out, \.\.\.; not analyzed; set [0-9a-f]{8}\): "coverage\/", "dist\/", "packages\/web\/\.next\/", "packages\/web\/build\/"\./,
    );
    expect(entry?.note).toContain("Move code out");
    expect(entry?.note).not.toContain(".git");
    expect((entry?.note ?? "").length).toBeLessThanOrEqual(MAX_NOTE_LENGTH);
  });

  it("keeps a Node repository with dist/index.js completed", async () => {
    const root = project({
      "src/a.ts": SRC,
      "dist/index.js": SRC,
      "dist/style.css": "a{}",
      "build/main.mjs": SRC,
    });
    expect(area(await scanSourceCode(root), "source:build-output")?.status).toBe("completed");
  });

  it("still skips tsc output: dist/ and out/ with .js, .d.ts and .map only", async () => {
    const root = project({
      "src/a.ts": VULN_TS,
      "dist/a.js": VULN_TS,
      "dist/a.d.ts": "export {};\n",
      "dist/a.js.map": "{}",
      "out/b.js": VULN_TS,
      "out/b.d.ts": "export {};\n",
    });
    const result = await scanSourceCode(root);
    const entry = area(result, "source:build-output");
    expect(entry?.status).toBe("completed");
    expect(entry?.note).toMatch(/^2 directories skipped by name/);
    expect(result.findings.map((finding) => finding.location.path)).toEqual(["src/a.ts"]);
  });

  it("is partial when nothing but skipped directories exist, and says why", async () => {
    const root = project({ "dist/index.js": SRC, "README.md": "x" });
    const entry = area(await scanSourceCode(root), "source:build-output");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("No source file was found outside these directories.");
  });

  it("does not count a track-language file as missing source (Python next to dist/)", async () => {
    const root = project({ "app/main.py": "print('x')\n", "dist/index.js": SRC });
    expect(area(await scanSourceCode(root), "source:build-output")?.status).toBe("completed");
  });

  it("does not turn partial because the only source is excluded by the project config", async () => {
    const root = project({ "legacy/a.ts": SRC, "dist/index.js": SRC });
    const projectConfig: ProjectConfig = {
      version: 1,
      exclude: ["legacy/**"],
      testDirectories: [],
      suppressions: [],
    };
    const entry = area(await scanSourceCode(root, { projectConfig }), "source:build-output");
    expect(entry?.status).toBe("completed");
  });

  it("walks a VS Code-like build/ of first-party TypeScript: findings reported, completed", async () => {
    const root = project({
      "src/a.ts": SRC,
      "build/lib/x.js": SRC,
      "build/gulpfile.ts": VULN_TS,
      "build/gulpfile.d.ts": "export {};\n",
      "dist/index.js": SRC,
    });
    const result = await scanSourceCode(root);
    expect(result.findings.map((finding) => finding.location.path)).toContain("build/gulpfile.ts");
    const entry = area(result, "source:build-output");
    expect(entry?.status).toBe("completed");
    expect(entry?.note).toMatch(/^1 directory skipped by name/);
    expect(entry?.note).toContain("1 more walked because they contain source.");
  });

  it("lists the walked directories when none was skipped (scripts/build/release.ts)", async () => {
    const root = project({
      "src/a.ts": SRC,
      "scripts/build/release.ts": VULN_TS,
      "tools/dist/gen.py": "x = 1\n",
    });
    const result = await scanSourceCode(root);
    expect(result.findings.map((finding) => finding.location.path)).toContain(
      "scripts/build/release.ts",
    );
    const entry = area(result, "source:build-output");
    expect(entry?.status).toBe("completed");
    expect(entry?.note).toMatch(
      /^2 skip-named directories \(dist, build, out, \.\.\.\) walked because they contain source \(set [0-9a-f]{8}\): "scripts\/build\/", "tools\/dist\/"\.$/,
    );
  });

  it("walks Go, Python, PHP, Java, Kotlin and TypeScript source in a skip-named directory", async () => {
    for (const file of [
      "out/a.py",
      "out/a.php",
      "out/A.java",
      "out/A.kt",
      "out/a.kts",
      "out/a.tsx",
    ]) {
      const root = project({ "src/a.ts": SRC, [file]: "x" });
      const entry = area(await scanSourceCode(root), "source:build-output");
      expect(entry?.status, file).toBe("completed");
      expect(entry?.note, file).toMatch(
        /^1 skip-named directory .* walked because it contains source/,
      );
    }
    const go = project({ "cmd/main.go": "package main\n", "build/build.go": "package build\n" });
    expect(area(await scanSourceCode(go), "source:build-output")?.note).toContain('"build/"');
  });

  it("records the walked directories in a structured field, redacted", async () => {
    const root = project({
      "src/a.ts": SRC,
      "build/index.ts": SRC,
      "build/lib/y.ts": VULN_TS,
      "coverage/lcov.js": SRC,
      [`pkg-${AWS_KEY}/dist/gen.py`]: "x = 1\n",
    });
    const result = await scanSourceCode(root);
    const walked = area(result, "source:build-output")?.walkedDirectories;
    expect(walked?.complete).toBe(true);
    expect(walked?.paths).toHaveLength(2);
    expect(walked?.paths).toContain("build");
    expect(JSON.stringify(walked)).not.toContain(AWS_KEY);
    expect(result.findings.map((finding) => finding.location.path)).toContain("build/lib/y.ts");
    const none = await scanSourceCode(project({ "src/a.ts": SRC, "dist/a.js": SRC }));
    expect(area(none, "source:build-output")?.walkedDirectories).toEqual({
      paths: [],
      complete: true,
    });
  });

  it("probes nested skip-named directories one at a time", async () => {
    const root = project({
      "src/a.ts": SRC,
      "build/index.ts": SRC,
      "build/out/gen.js": SRC,
      "build/dist/real.ts": SRC,
    });
    const entry = area(await scanSourceCode(root), "source:build-output");
    expect(entry?.note).toMatch(/^1 directory skipped by name .*"build\/out\/"/);
    expect(entry?.note).toContain("2 more walked");
  });

  it("walks a package named build under a JVM source root with a manifest", async () => {
    const root = project({
      "src/main/java/com/acme/build/sub/Foo.java": JAVA,
      "pom.xml": "<project/>",
    });
    const result = await scanSourceCode(root);
    expect(result.findings.some((f) => f.location.path?.endsWith("build/sub/Foo.java"))).toBe(true);
    expect(area(result, "source:java")?.note).toMatch(/^1 Java file/);
  });

  it("finds the manifest in any ancestor: a subproject pom, a root settings.gradle.kts", async () => {
    const sub = project({
      "services/api/pom.xml": "<project/>",
      "services/api/src/main/java/com/acme/build/sub/Foo.java": JAVA,
    });
    expect(area(await scanSourceCode(sub), "source:java")?.note).toMatch(/^1 Java file/);
    const gradle = project({
      "settings.gradle.kts": "x",
      "app/src/main/kotlin/com/acme/out/sub/Foo.kt": "fun f() {}\n",
    });
    expect(area(await scanSourceCode(gradle), "source:kotlin")?.note).toMatch(/^1 Kotlin file/);
    for (const manifest of ["build.gradle", "build.gradle.kts", "settings.gradle"]) {
      const other = project({
        [manifest]: "x",
        "src/main/java/a/build/sub/Foo.java": JAVA,
      });
      expect(area(await scanSourceCode(other), "source:java")?.note, manifest).toMatch(
        /^1 Java file/,
      );
    }
  });

  it("does not walk a JVM-looking root without a manifest, unless the directory holds source", async () => {
    const nested = project({ "app.ts": SRC, "src/main/java/build/sub/Foo.java": JAVA });
    const skipped = area(await scanSourceCode(nested), "source:build-output");
    expect(skipped?.note).toMatch(/^1 directory skipped by name/);
    const direct = project({ "app.ts": SRC, "src/main/java/build/Foo.java": JAVA });
    expect(area(await scanSourceCode(direct), "source:java")?.note).toMatch(/^1 Java file/);
  });

  it("recognises JVM source roots", () => {
    for (const yes of [
      "src/main/java/build",
      "src/test/kotlin/com/out",
      "app/src/main/java/a/dist",
      "src/integrationTest/java/x/Foo.java",
      "src/main/java/com/acme/build/Foo.java",
    ]) {
      expect(isUnderJvmSourceRoot(yes), yes).toBe(true);
    }
    for (const no of [
      "build",
      "src/build",
      "java/build",
      "src/main/build",
      "lib/java/build",
      "src/java/build",
      "src/main/java",
      "build/src/main/x",
    ]) {
      expect(isUnderJvmSourceRoot(no), no).toBe(false);
    }
  });

  it("does not count declaration files, maps or JavaScript as source", async () => {
    const dist = project({
      "app.py": "x=1\n",
      "dist/index.js": SRC,
      "dist/index.d.ts": "export {};\n",
      "dist/index.js.map": "{}",
    });
    expect(area(await scanSourceCode(dist), "source:build-output")?.note).toMatch(
      /^1 directory skipped by name/,
    );
  });

  it("notes when the source check hit its directory cap", async () => {
    const files: Record<string, string> = { "src/a.ts": SRC };
    for (let index = 0; index < 202; index += 1) files[`p${index}/dist/x.js`] = SRC;
    const entry = area(await scanSourceCode(project(files)), "source:build-output");
    expect(entry?.note).toContain("first 200 checked for source");
    expect((entry?.note ?? "").length).toBeLessThanOrEqual(MAX_NOTE_LENGTH);
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

  it("fingerprints the whole set, in any order, including the walked ones", () => {
    const names = Array.from({ length: 7 }, (_, index) => `d${index}/dist`);
    const base = noteOf(names);
    expect(noteOf([...names].reverse())).toBe(base);
    // Same count and same five listed paths; only the unlisted tail differs.
    expect(noteOf([...names.slice(0, 6), "zz/out"])).not.toBe(base);
    expect(noteOf(names, { walked: ["a/build"] })).not.toBe(noteOf(names, { walked: ["b/build"] }));
    expect(noteOf(["dist"], { walked: ["a/build"] })).toContain("1 more walked");
    const walkedOnly = (list: string[]) =>
      describeSkippedBuildDirectories({ paths: [], walked: list, noSourceElsewhere: false });
    expect(walkedOnly(["a/build", "b/out"])).not.toBe(walkedOnly(["a/build", "b/dist"]));
    expect(walkedOnly(["a/build"])).toMatch(
      /^1 skip-named directory .* walked because it contains/,
    );
  });

  it("caps the list, counts the rest, and sanitises hostile names", () => {
    const many = Array.from({ length: 8 }, (_, index) => `d${7 - index}/dist`);
    expect(noteOf(many)).toMatch(
      /^8 directories skipped by name \(dist, build, out, \.\.\.; not analyzed; set [0-9a-f]{8}\): "d0\/dist\/", "d1\/dist\/", "d2\/dist\/", "d3\/dist\/", "d4\/dist\/" and 3 more\./,
    );
    expect(noteOf(["dist"])).toMatch(/^1 directory skipped by name/);
    const long = Array.from({ length: 6 }, (_, i) => `${"a".repeat(200)}${i}/build`);
    const hostile = noteOf([HOSTILE, ...long]);
    expect(hostile.length).toBeLessThanOrEqual(MAX_NOTE_LENGTH);
    expect(hostile).not.toMatch(CONTROL);
    expect(hostile).not.toContain(FAKE_KEY);
    expect(hostile).toMatch(/and \d+ more\./);
  });

  it("redacts before measuring: a key in a directory name cannot push the note over the limit", () => {
    const keys = Array.from({ length: 6 }, (_, index) => `x${index}-${AWS_KEY}/dist`);
    for (const input of [
      { paths: keys, noSourceElsewhere: true, limitReached: true, probeLimit: 200, walked: keys },
      { paths: [], walked: keys, noSourceElsewhere: false, limitReached: true, probeLimit: 200 },
    ]) {
      const note = describeSkippedBuildDirectories(input);
      expect(note.length).toBeLessThanOrEqual(MAX_NOTE_LENGTH);
      expect(note).not.toContain(AWS_KEY);
    }
    expect(
      describeSkippedResourceXml(keys.map((item) => `res/${item}.xml`)).length,
    ).toBeLessThanOrEqual(MAX_NOTE_LENGTH);
  });

  it("keeps the longest possible note within the limit even with nothing listed", () => {
    const long = `${"z".repeat(400)}/dist`;
    const note = describeSkippedBuildDirectories({
      paths: [long],
      walked: [long],
      noSourceElsewhere: true,
      limitReached: true,
      probeLimit: 200,
    });
    expect(note.length).toBeLessThanOrEqual(MAX_NOTE_LENGTH);
    expect(note).toContain("file limit reached");
    expect(note).toContain("No source file was found outside these directories.");
  });

  it("changes the note with each reason and tail, and drops them when they do not apply", () => {
    const plain = noteOf(["dist"]);
    expect(plain).not.toMatch(/No source file|walked|file limit|first 200/);
    expect(noteOf(["dist"], { noSourceElsewhere: true })).toContain(
      " No source file was found outside these directories. Move",
    );
    expect(noteOf(["dist"], { limitReached: true })).toContain(
      "(file limit reached; count may be incomplete) Move",
    );
    expect(noteOf(["dist"], { probeLimit: 200 })).toContain("(first 200 checked for source) Move");
  });
});

describe("XML under res/ or target/", () => {
  const ANDROID = { "settings.gradle": "x", "app/src/main/res/layout/main.xml": "<LinearLayout/>" };

  it("counts it as skipped in a JVM project instead of dropping it", async () => {
    const root = project({
      "src/a.ts": SRC,
      "Main.kt": "fun f() {}\n",
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

  it("recognises a JVM project by its manifest alone (Gradle, Maven)", async () => {
    for (const manifest of ["build.gradle", "build.gradle.kts", "pom.xml"]) {
      const root = project({ ...ANDROID, [manifest]: "x" });
      expect(area(await scanSourceCode(root), "source:xml-skipped"), manifest).toBeDefined();
    }
  });

  it("is not reported for a project that is not JVM", async () => {
    const root = project({ "src/a.ts": SRC, "assets/res/icons.xml": "<a/>" });
    expect(area(await scanSourceCode(root), "source:xml-skipped")).toBeUndefined();
  });

  it("stays within the note limit with hostile names, and adds the limit tail", () => {
    const note = describeSkippedResourceXml([
      `res/${HOSTILE}.xml`,
      ...Array.from({ length: 6 }, (_, i) => `${"b".repeat(150)}${i}/res/a.xml`),
    ]);
    expect(note.length).toBeLessThanOrEqual(MAX_NOTE_LENGTH);
    expect(note).not.toMatch(CONTROL);
    expect(describeSkippedResourceXml(["res/a.xml"], true)).toMatch(
      /\(file limit reached; count may be incomplete\)$/,
    );
  });
});

describe("unreadable and special files", () => {
  const posix = process.platform !== "win32";

  it.skipIf(!posix || process.getuid?.() === 0)(
    "counts files whose lstat fails as partial",
    async () => {
      const root = project({ "src/a.ts": SRC, "locked/b.ts": SRC, "locked/c.xml": "<a/>" });
      const locked = path.join(root, "locked");
      chmodSync(locked, 0o644); // listable, not searchable: lstat of the entries fails with EACCES
      restore.push(locked);
      const entry = area(await scanSourceCode(root), "source:unreadable-files");
      expect(entry).toMatchObject({ status: "partial", ruleIds: [] });
      expect(entry?.note).toMatch(
        /^2 files could not be read \(permission error or removed during the scan, not analyzed; set [0-9a-f]{8}\): "locked\/b\.ts", "locked\/c\.xml"\.$/,
      );
    },
  );

  it.skipIf(!posix)("counts an analysable-named FIFO once and never opens it", async () => {
    const root = project({ "src/a.ts": SRC });
    execFileSync("mkfifo", [path.join(root, "pipe.ts")]);
    const entry = area(await scanSourceCode(root), "source:special-files");
    expect(entry).toMatchObject({ status: "completed", ruleIds: [] });
    expect(entry?.note).toMatch(
      /^1 special file skipped \(FIFO, socket, device or not a regular file, never opened; set [0-9a-f]{8}\): "pipe\.ts"\.$/,
    );
  });

  it.skipIf(!posix)("ignores sockets and FIFOs that are no source names", async () => {
    const root = project({ "src/a.ts": SRC });
    execFileSync("mkfifo", [path.join(root, "dev.sock")]);
    execFileSync("mkfifo", [path.join(root, ".s.PGSQL.5432")]);
    expect(area(await scanSourceCode(root), "source:special-files")).toBeUndefined();
  });

  it("keeps both notes within the limit, sanitised, with the limit tail", () => {
    const names = [HOSTILE, ...Array.from({ length: 7 }, (_, i) => `${"c".repeat(180)}${i}`)];
    for (const note of [describeUnreadableEntries(names), describeSpecialFiles(names)]) {
      expect(note.length).toBeLessThanOrEqual(MAX_NOTE_LENGTH);
      expect(note).not.toMatch(CONTROL);
      expect(note).not.toContain(FAKE_KEY);
    }
    for (const note of [
      describeUnreadableEntries(["a.ts"], true),
      describeSpecialFiles(["a.ts"], true),
    ]) {
      expect(note).toMatch(/\(file limit reached; count may be incomplete\)$/);
    }
  });
});

describe("JVM XML without Java files", () => {
  const KOTLIN = "fun f() {}\n";
  const BIG_XML = `<mapper>${"<!-- pad -->".repeat(100_000)}</mapper>`;

  it("reports XML over 1 MiB in a Kotlin-only project", async () => {
    const root = project({ "src/main/kotlin/A.kt": KOTLIN, "src/main/resources/big.xml": BIG_XML });
    const entry = area(await scanSourceCode(root), "source:mybatis");
    expect(entry).toMatchObject({ status: "partial", ruleIds: [] });
    expect(entry?.note).toMatch(/1 XML file\(s\) were binary, unreadable or over 1 MiB/);
  });

  it("reports it for a manifest-only project (no Java or Kotlin file at all)", async () => {
    for (const manifest of ["pom.xml", "build.gradle", "build.gradle.kts"]) {
      const root = project({ [manifest]: "<project/>", "conf/big.xml": BIG_XML });
      expect(area(await scanSourceCode(root), "source:mybatis")?.status, manifest).toBe("partial");
    }
  });

  it("stays quiet for a project that is not JVM", async () => {
    const root = project({ "src/a.ts": SRC, "conf/big.xml": BIG_XML });
    expect(area(await scanSourceCode(root), "source:mybatis")).toBeUndefined();
  });
});

describe("file limit reached", () => {
  it.skipIf(process.platform === "win32" || process.getuid?.() === 0)(
    "adds the limit tail to the xml-skipped and unreadable notes of a scan",
    async () => {
      const files: Record<string, string> = {
        "pom.xml": "<project/>",
        "zres/res/layout.xml": "<a/>",
        "zlocked/b.ts": SRC,
      };
      // Visited last (the walk pops the last-sorted directory first), so the two entries above are
      // recorded before the walk stops at MAX_FILES.
      const root = project(files);
      mkdirSync(path.join(root, "a"));
      for (let index = 0; index <= MAX_FILES; index += 1) {
        writeFileSync(path.join(root, "a", `f${index}.ts`), "");
      }
      const locked = path.join(root, "zlocked");
      chmodSync(locked, 0o644);
      restore.push(locked);
      const result = await scanSourceCode(root);
      const tail = /\(file limit reached; count may be incomplete\)$/;
      expect(area(result, "source:xml-skipped")?.note).toMatch(tail);
      expect(area(result, "source:unreadable-files")?.note).toMatch(tail);
    },
    180_000,
  );
});
