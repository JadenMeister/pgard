import { createHash } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanSourceCode } from "../scan-source.js";
import { MAX_FILES, walkSourceTree } from "../walk.js";
import {
  detectGradleCatalogFrameworks,
  detectComposerFrameworks,
  detectGradleFrameworks,
  detectFrameworks,
  detectMavenFrameworks,
  detectPyprojectFrameworks,
  detectRequirementsFrameworks,
  stripGradleComments,
} from "./detect-frameworks.js";
import {
  MAX_PARSE_TIMEOUTS_PER_LANGUAGE,
  MAX_TRACK_PARSE_MS,
  createTrackDeadline,
  detectLanguageTrack,
  languageTrackCoverage,
  parseCoverage,
  parseTrackFiles,
} from "./language-track.js";
import { GRAMMAR_SHA256, grammarPath, TREE_SITTER_LANGUAGES } from "./languages.js";
import { TreeSitterRuntime } from "./runtime.js";

const roots: string[] = [];
function project(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-wt-")));
  roots.push(root);
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
    writeFileSync(path.join(root, name), content);
  }
  return root;
}
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe("vendored grammars", () => {
  for (const language of TREE_SITTER_LANGUAGES) {
    it(`${language} wasm matches the recorded SHA-256`, () => {
      const digest = createHash("sha256")
        .update(readFileSync(grammarPath(language)))
        .digest("hex");
      expect(digest).toBe(GRAMMAR_SHA256[language]);
    });
  }
});

describe("virtual environments and generated directories", () => {
  it("never skips JavaScript under a plain venv/ directory", async () => {
    const root = project({
      "app/venv/server.js": `const cp = require("child_process");\nmodule.exports = (req) => cp.exec(req.query.x);\n`,
    });
    const output = await scanSourceCode(root);
    expect(output.findings.length).toBeGreaterThan(0);
    const javascript = output.coverage.find((entry) => entry.area === "source:javascript");
    expect(javascript?.note ?? "").not.toContain("No JavaScript files found");
  });

  it("analyzes a directory called venv or site-packages without pyvenv.cfg", async () => {
    const root = project({
      "Lib/venv/__init__.py": "x = 1\n",
      "venv/app.py": "x = 1\n",
      "src/site-packages/mod.py": "x = 1\n",
    });
    const walk = await walkSourceTree(root);
    expect(walk.trackFiles.python.map((file) => file.relativePath)).toEqual([
      "Lib/venv/__init__.py",
      "src/site-packages/mod.py",
      "venv/app.py",
    ]);
    expect(walk.skippedDependencyDirectories).toEqual([]);
  });

  it("skips a real virtual environment (pyvenv.cfg) and site-packages under lib/python", async () => {
    const root = project({
      "env/pyvenv.cfg": "home = /usr/bin\n",
      "env/bin/activate": "",
      "env/lib/python3.12/site-packages/dep.py": "x = 1\n",
      "docs/lib/python3.11/site-packages/dep.py": "x = 1\n",
      "src/main.py": "x = 1\n",
    });
    const walk = await walkSourceTree(root);
    expect(walk.trackFiles.python.map((file) => file.relativePath)).toEqual(["src/main.py"]);
    expect(walk.skippedDependencyDirectories).toEqual([
      { path: "env", reason: "Python virtual environment" },
      { path: "docs/lib/python3.11/site-packages", reason: "Python site-packages" },
    ]);
  });

  it("does not treat a lone pyvenv.cfg as a virtualenv", async () => {
    const root = project({
      "src/pyvenv.cfg": "",
      "src/hidden.js": "module.exports = 1;\n",
      "src/hidden.py": "x = 1\n",
      "winenv/pyvenv.cfg": "home = C:\\Python\n",
      "winenv/Lib/site-packages/dep.py": "x = 1\n",
    });
    const walk = await walkSourceTree(root);
    expect(walk.files.map((file) => file.relativePath)).toEqual(["src/hidden.js"]);
    expect(walk.trackFiles.python.map((file) => file.relativePath)).toEqual(["src/hidden.py"]);
    expect(walk.skippedDependencyDirectories).toEqual([
      { path: "winenv", reason: "Python virtual environment" },
    ]);
  });

  it("skips Maven target/ and Gradle .gradle/ only next to their build files", async () => {
    const root = project({
      "svc/pom.xml": "<project/>",
      "svc/target/gen/Gen.java": "class Gen {}\n",
      "svc/src/Main.java": "class Main {}\n",
      "lib/build.gradle": "",
      "lib/.gradle/cache/X.java": "class X {}\n",
      "other/target/Keep.java": "class Keep {}\n",
    });
    const walk = await walkSourceTree(root);
    expect(walk.trackFiles.java.map((file) => file.relativePath)).toEqual([
      "other/target/Keep.java",
      "svc/src/Main.java",
    ]);
    const skipped = walk.skippedDependencyDirectories.map((entry) => entry.reason).sort();
    expect(skipped).toEqual(["Gradle cache", "Maven build output"]);
    const output = await scanSourceCode(root);
    const note = output.coverage.find((entry) => entry.area === "source:dependency-directories");
    expect(note?.note).toContain("third-party or generated code");
  });

  it("marks the track lists as lower bounds when the walk stops at MAX_FILES", async () => {
    const root = project({ "a.py": "x = 1\n" });
    for (let i = 0; i <= MAX_FILES; i += 1) writeFileSync(path.join(root, `f${i}.js`), "");
    const walk = await walkSourceTree(root);
    expect(walk.isTruncated).toBe(true);
    expect(walk.trackTruncated).toBe(true);
    const coverage = languageTrackCoverage(await detectLanguageTrack(walk));
    expect(coverage[0]?.note).toContain("at least");
  }, 60_000);
});

describe("more manifests", () => {
  it("detects frameworks from requirements/, Pipfile, setup.py, setup.cfg and the Gradle catalog", async () => {
    const root = project({
      "requirements/base.txt": "Django>=4\n",
      Pipfile: '[packages]\nflask = "*"\n',
      "setup.py": 'setup(name="x", install_requires=["fastapi"])\n',
      "gradle/libs.versions.toml":
        '[libraries]\nspring = { module = "org.springframework.boot:spring-boot-starter" }\n',
      "src/Main.java": "class Main {}\n",
    });
    const walk = await walkSourceTree(root);
    // setup.py is also Python source.
    expect(walk.trackFiles.python.map((file) => file.relativePath)).toEqual(["setup.py"]);
    const detection = await detectFrameworks(walk.trackManifests);
    expect(detection.frameworks.map((entry) => entry.framework).sort()).toEqual([
      "Django",
      "FastAPI",
      "Flask",
      "Spring",
    ]);
    expect(detectGradleCatalogFrameworks("# org.springframework\n")).toEqual([]);
  });

  it("keeps // inside Gradle strings when stripping comments", () => {
    const script = `repositories { maven { url "https://repo.example/x" } }\n// comment\n/* block */ implementation 'org.springframework:spring-core' // tail\n`;
    const stripped = stripGradleComments(script);
    expect(stripped).toContain("https://repo.example/x");
    expect(stripped).not.toContain("comment");
    expect(stripped).not.toContain("tail");
    expect(detectGradleFrameworks(script)).toEqual(["Spring"]);
    expect(detectGradleFrameworks(`url "https://a" // org.springframework\n`)).toEqual([]);
    expect(stripGradleComments("/* ".repeat(200_000)).length).toBe(0);
  });
});

describe("regular expression cost", () => {
  it("handles a catalog and manifests made of newlines and blanks quickly", async () => {
    const megabyte = 1024 * 1024;
    const inputs = ["\n".repeat(megabyte), " \n".repeat(megabyte / 2), "#\n".repeat(megabyte / 2)];
    const startedAt = Date.now();
    for (const input of inputs) {
      expect(detectGradleCatalogFrameworks(input)).toEqual([]);
      expect(detectGradleFrameworks(input)).toEqual([]);
      expect(detectPyprojectFrameworks(input)).toEqual([]);
      expect(detectRequirementsFrameworks(input).frameworks).toEqual([]);
      expect(detectMavenFrameworks(input)).toEqual([]);
      expect(detectComposerFrameworks(input)).toBe("invalid_json");
    }
    expect(Date.now() - startedAt).toBeLessThan(10_000);
  });

  it("handles repeated groupId openers and blanks quickly", () => {
    const startedAt = Date.now();
    expect(detectMavenFrameworks("<groupId>".repeat(100_000) + " ".repeat(500_000))).toEqual([]);
    expect(detectMavenFrameworks("<groupId> ".repeat(100_000))).toEqual([]);
    expect(Date.now() - startedAt).toBeLessThan(10_000);
  });
});

describe("scan-wide parse limits", () => {
  const manyFiles = (count: number) =>
    Object.fromEntries(Array.from({ length: count }, (_, i) => [`f${i}.py`, "x = 1\n"]));

  it("stops at the scan-wide deadline and marks the rest partial", async () => {
    const walk = await walkSourceTree(project(manyFiles(6)));
    let time = 0;
    const deadline = createTrackDeadline(100, () => time);
    const runtime = new TreeSitterRuntime();
    let parsed = 0;
    const stats = await parseTrackFiles(
      runtime,
      "python",
      walk.trackFiles.python,
      { deadline },
      () => {
        parsed += 1;
        time += 40;
      },
    );
    expect(parsed).toBe(3);
    expect(stats).toMatchObject({ parsed: 3, notParsed: 3, files: 6, stoppedBy: "deadline" });
    const coverage = parseCoverage("python", [], stats);
    expect(coverage.status).toBe("partial");
    expect(coverage.note).toContain("scan-wide budget");
    expect(coverage.note).toContain("3 of 6 file(s) were not parsed");

    // A later language sees the same expired deadline and parses nothing.
    const javaWalk = await walkSourceTree(project({ "A.java": "class A {}\n" }));
    const later = await parseTrackFiles(runtime, "java", javaWalk.trackFiles.java, { deadline });
    expect(later).toMatchObject({ parsed: 0, notParsed: 1, stoppedBy: "deadline" });
    expect(runtime.loadedLanguages()).not.toContain("java");
  });

  it("stops after too many timeouts in one language", async () => {
    const root = project(
      Object.fromEntries(
        Array.from({ length: 6 }, (_, i) => [`f${i}.java`, "class A { int a; }\n".repeat(20_000)]),
      ),
    );
    const walk = await walkSourceTree(root);
    let tick = 0;
    const stats = await parseTrackFiles(new TreeSitterRuntime(), "java", walk.trackFiles.java, {
      timeoutMs: 10,
      now: () => (tick += 5),
      maxTimeouts: 2,
    });
    expect(stats).toMatchObject({ stoppedBy: "timeouts", notParsed: 4, files: 6 });
    expect(stats.timedOut).toHaveLength(2);
    const coverage = parseCoverage("java", [], stats, { timeoutMs: 10 });
    expect(coverage.status).toBe("partial");
    expect(coverage.note).toContain("stopped after 2 timeouts");
    expect(coverage.note).toContain("4 of 6 file(s) were not parsed");
  });

  it("exposes the defaults as named constants", () => {
    expect(MAX_TRACK_PARSE_MS).toBe(60_000);
    expect(MAX_PARSE_TIMEOUTS_PER_LANGUAGE).toBe(3);
  });
});
