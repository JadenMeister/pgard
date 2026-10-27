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
) => describeSkippedBuildDirectories({ paths, withSource: [], noSourceElsewhere: false, ...extra });

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

  it("is partial when no source was found anywhere, and says why", async () => {
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

  it("is partial and names a skipped Go directory that holds source", async () => {
    const root = project({
      "cmd/main.go": "package main\n",
      "build/build.go": "package build\n",
      "dist/index.js": SRC,
    });
    const entry = area(await scanSourceCode(root), "source:build-output");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain('"build/ (contains source)"');
    expect(entry?.note).toContain("Contains source files; skipped by name.");
    expect((entry?.note ?? "").length).toBeLessThanOrEqual(MAX_NOTE_LENGTH);
  });

  it("is partial for Python, PHP, Java and Kotlin files directly in a skipped directory", async () => {
    for (const file of ["out/a.py", "out/a.php", "out/A.java", "out/A.kt", "out/a.kts"]) {
      const root = project({ "src/a.ts": SRC, [file]: "x" });
      expect(area(await scanSourceCode(root), "source:build-output")?.status, file).toBe("partial");
    }
  });

  it("walks a package named build under a JVM source root like any other directory", async () => {
    const root = project({
      "src/main/java/com/acme/build/Foo.java": JAVA,
      "pom.xml": "<project/>",
    });
    const result = await scanSourceCode(root);
    expect(area(result, "source:build-output")).toBeUndefined();
    expect(result.findings.some((f) => f.location.path?.endsWith("build/Foo.java"))).toBe(true);
    expect(area(result, "source:java")?.note).toMatch(/^1 Java file/);
  });

  it("walks a Gradle package called build too, but not under a JavaScript repository", async () => {
    const gradle = project({
      "src/main/kotlin/com/acme/out/Foo.kt": "fun f() {}\n",
      "build.gradle.kts": "x",
      "build/classes/A.class": "x",
    });
    const result = await scanSourceCode(gradle);
    expect(area(result, "source:kotlin")?.note).toMatch(/^1 Kotlin file/);
    expect(area(result, "source:build-output")?.note).toMatch(/^1 director/);
    const js = project({ "app.ts": SRC, "src/main/java/build/Widget.js": SRC });
    const jsResult = await scanSourceCode(js);
    expect(jsResult.findings).toEqual([]);
    expect(area(jsResult, "source:build-output")?.note).toMatch(/^1 director/);
    const jsFiles = project({ "src/java/build/a.ts": SRC, "app.ts": SRC });
    expect(area(await scanSourceCode(jsFiles), "source:build-output")).toBeDefined();
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

  it("counts TypeScript in a skipped directory as source, but not declarations", async () => {
    const pkg = project({ "app.py": "x=1\n", "packages/angular/build/index.ts": "export {};\n" });
    expect(area(await scanSourceCode(pkg), "source:build-output")?.status).toBe("partial");
    const tsx = project({ "app.py": "x=1\n", "build/App.tsx": "export {};\n" });
    expect(area(await scanSourceCode(tsx), "source:build-output")?.status).toBe("partial");
    const dist = project({
      "app.py": "x=1\n",
      "dist/index.js": SRC,
      "dist/index.d.ts": "export {};\n",
      "dist/index.js.map": "{}",
    });
    expect(area(await scanSourceCode(dist), "source:build-output")?.status).toBe("completed");
  });

  it("says a directory holds source once: in its label, and in the tail", () => {
    const note = noteOf(["build"], { withSource: ["build"] });
    expect(note.match(/contains source/gi)).toHaveLength(2);
    expect(note).not.toContain("contains source files; skipped by name)");
  });

  it("changes the note with each reason and tail, and drops them when they do not apply", () => {
    const plain = noteOf(["dist"]);
    expect(plain).not.toMatch(/No source file|Contains source|file limit|first 200/);
    expect(noteOf(["dist"], { noSourceElsewhere: true })).toContain(
      " No source file was found outside these directories. Move",
    );
    expect(noteOf(["dist"], { limitReached: true })).toContain(
      "(file limit reached; count may be incomplete) Move",
    );
    expect(noteOf(["dist"], { probeLimit: 200 })).toContain("(first 200 checked for source) Move");
    expect(noteOf(["dist"], { withSource: ["dist"] })).toContain(
      " Contains source files; skipped by name. Move",
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

  it("fingerprints the whole set, in any order, including which entries hold source", () => {
    const names = Array.from({ length: 7 }, (_, index) => `d${index}/dist`);
    const base = noteOf(names);
    expect(noteOf([...names].reverse())).toBe(base);
    // Same count and same five listed paths; only the unlisted tail differs.
    expect(noteOf([...names.slice(0, 6), "zz/out"])).not.toBe(base);
    const withSix = noteOf(names, { withSource: names.slice(0, 6) });
    const withLast = noteOf(names, { withSource: [...names.slice(0, 5), names[6] as string] });
    expect(withSix).not.toBe(withLast);
    expect(withSix).not.toBe(base);
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
    for (const paths of [keys]) {
      for (const input of [
        { paths, withSource: [], noSourceElsewhere: true, limitReached: true, probeLimit: 200 },
        { paths, withSource: paths, noSourceElsewhere: true, limitReached: true, probeLimit: 200 },
      ]) {
        const note = describeSkippedBuildDirectories(input);
        expect(note.length).toBeLessThanOrEqual(MAX_NOTE_LENGTH);
        expect(note).not.toContain(AWS_KEY);
      }
    }
    expect(
      describeSkippedResourceXml(keys.map((item) => `res/${item}.xml`)).length,
    ).toBeLessThanOrEqual(MAX_NOTE_LENGTH);
  });

  it("keeps the longest possible note within the limit even with nothing listed", () => {
    const note = describeSkippedBuildDirectories({
      paths: [`${"z".repeat(400)}/dist`],
      withSource: [`${"z".repeat(400)}/dist`],
      noSourceElsewhere: true,
      limitReached: true,
      probeLimit: 200,
    });
    expect(note.length).toBeLessThanOrEqual(MAX_NOTE_LENGTH);
    expect(note).toContain("file limit reached");
    expect(note).toContain("No source file was found outside these directories.");
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
