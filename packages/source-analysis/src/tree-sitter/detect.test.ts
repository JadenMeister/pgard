import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanSourceCode } from "../scan-source.js";
import { runFixtures, listFixtures, validateFixtureLayout } from "../test-support/fixtures.js";
import { walkSourceTree } from "../walk.js";
import {
  detectComposerFrameworks,
  detectGradleFrameworks,
  detectMavenFrameworks,
  detectPyprojectFrameworks,
  detectRequirementsFrameworks,
} from "./detect-frameworks.js";
import { detectLanguageTrack, languageTrackCoverage } from "./language-track.js";

/** Slow Windows runners get three times the room; elsewhere the limits stay tight. */
const SLOW = process.platform === "win32" ? 3 : 1;

const roots: string[] = [];
function project(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-det-")));
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

describe("manifest parsing", () => {
  it("detects Spring from Maven and Gradle", () => {
    const pom = `<project><dependencies><dependency>
      <groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId>
      </dependency></dependencies></project>`;
    expect(detectMavenFrameworks(pom)).toEqual(["Spring"]);
    expect(
      detectMavenFrameworks("<project><!-- <groupId>org.springframework</groupId> --></project>"),
    ).toEqual([]);
    expect(
      detectGradleFrameworks(`implementation 'org.springframework.boot:spring-boot-starter'`),
    ).toEqual(["Spring"]);
    expect(detectGradleFrameworks(`// org.springframework\nplugins { }`)).toEqual([]);
  });

  it("detects Python frameworks by exact package name", () => {
    expect(
      detectRequirementsFrameworks(
        "# comment\nDjango==4.2\nflask-cors>=3\n-r other.txt\nfastapi[all]\n",
      ).frameworks.sort(),
    ).toEqual(["Django", "FastAPI"]);
    expect(
      detectPyprojectFrameworks(
        `[project]\nname = "flask"\ndependencies = ["flask>=3", "django-filter"]\n# fastapi\n`,
      ),
    ).toEqual(["Flask"]);
  });

  it("detects Laravel and Symfony from composer.json", () => {
    expect(
      detectComposerFrameworks(
        JSON.stringify({
          require: { "laravel/framework": "^11" },
          "require-dev": { "symfony/http-kernel": "*" },
        }),
      ),
    ).toEqual(["Laravel", "Symfony"]);
    expect(detectComposerFrameworks("{not json")).toBe("invalid_json");
    expect(detectComposerFrameworks("[1,2]")).toEqual([]);
  });
});

describe("language detection and coverage", () => {
  it("reports detected languages as not_tested with the note", async () => {
    const root = project({
      "pom.xml": "<project><groupId>org.springframework.boot</groupId></project>",
      "src/Main.java": "class Main {}\n",
      "app/Main.kt": "class Main\n",
      "requirements.txt": "flask\n",
      "svc/app.py": "x = 1\n",
      "composer.json": JSON.stringify({ require: { "laravel/framework": "^11" } }),
      "web/index.php": "<?php echo 1;\n",
      ".venv/pyvenv.cfg": "home = /usr/bin\n",
      ".venv/bin/activate": "",
      ".venv/lib/site.py": "x = 1\n",
    });
    const coverage = languageTrackCoverage(await detectLanguageTrack(await walkSourceTree(root)));
    expect(coverage.map((entry) => [entry.area, entry.status])).toEqual([
      ["source:java", "not_tested"],
      ["source:kotlin", "not_tested"],
      ["source:python", "not_tested"],
      ["source:php", "not_tested"],
    ]);
    for (const entry of coverage) expect(entry.note).toContain("detected, no rules yet");
    expect(coverage[0]?.note).toContain("Spring");
    expect(coverage[1]?.note).toContain("Spring");
    expect(coverage[2]?.note).toContain("Flask");
    expect(coverage[2]?.note).toContain("1 file(s)");
    expect(coverage[3]?.note).toContain("Laravel");
  });

  it("appears in the source scan coverage and loads nothing for a language without files", async () => {
    const root = project({ "A.java": "class A {}\n", "a.php": "<?php\n" });
    const output = await scanSourceCode(root);
    // Java has the SQL injection rule: it is analyzed, not "detected, no rules yet".
    expect(output.coverage.find((item) => item.area === "source:java")).toMatchObject({
      status: "completed",
      ruleIds: [
        "PG-SQL-005",
        "PG-XSS-004",
        "PG-SSRF-002",
        "PG-CMD-003",
        "PG-PATH-002",
        "PG-COOKIE-001",
        "PG-CSRF-001",
        "PG-CONF-001",
      ],
    });
    // PHP has the SQL injection and command execution rules.
    expect(output.coverage.find((item) => item.area === "source:php")).toMatchObject({
      status: "completed",
      ruleIds: ["PG-SQL-007", "PG-CMD-005"],
    });
    expect(output.coverage.some((item) => item.area === "source:kotlin")).toBe(false);
  });
});

describe("malicious manifests", () => {
  it("does not expand XML entities or read a DTD", async () => {
    const pom = `<?xml version="1.0"?>
<!DOCTYPE project [<!ENTITY xxe SYSTEM "file:///etc/passwd"><!ENTITY a "&b;&b;"><!ENTITY b "&c;&c;">]>
<project><groupId>&xxe;</groupId><artifactId>org.springframework</artifactId></project>`;
    expect(detectMavenFrameworks(pom)).toBe("unsafe_xml");
    const root = project({ "pom.xml": pom, "A.java": "class A {}\n" });
    const detection = await detectLanguageTrack(await walkSourceTree(root));
    expect(detection.languages[0]?.frameworks).toEqual([]);
    const coverage = languageTrackCoverage(detection);
    const manifests = coverage.find((entry) => entry.area === "source:manifests");
    expect(manifests?.status).toBe("partial");
    expect(manifests?.note).toContain("DTD or entities");
  });

  it("skips huge manifests and stays fast on pathological input", async () => {
    const huge = "<!--".repeat(300_000);
    const root = project({
      "composer.json": `{"require":{"laravel/framework":"1"},"pad":"${"x".repeat(2 * 1024 * 1024)}"}`,
      "pom.xml": huge,
      "build.gradle": "/*".repeat(400_000),
      "A.java": "class A {}\n",
      "a.php": "<?php\n",
    });
    const startedAt = Date.now();
    const detection = await detectLanguageTrack(await walkSourceTree(root));
    expect(Date.now() - startedAt).toBeLessThan(5000 * SLOW);
    expect(detection.manifestIssues.map((issue) => [issue.path, issue.reason])).toContainEqual([
      "composer.json",
      "unreadable_or_too_large",
    ]);
    expect(detection.languages.find((entry) => entry.language === "php")?.frameworks).toEqual([]);
    const note = languageTrackCoverage(detection).find(
      (entry) => entry.area === "source:manifests",
    );
    expect(note?.status).toBe("partial");
  }, 60_000);
});

describe("fixture layout", () => {
  it("follows the convention", () => {
    expect(validateFixtureLayout()).toEqual([]);
  });

  it("reports violations in a broken tree", () => {
    const root = project({
      "java/injection/vulnerable/A.java": "",
      "java/injection/other/A.java": "",
      "java/injection/safe/A.py": "",
      "java/not-a-category/safe/A.java": "",
      "cobol/x.txt": "",
    });
    expect(validateFixtureLayout(root)).toHaveLength(4);
  });

  it("runs vulnerable and safe cases through a detector", async () => {
    const root = project({
      "java/injection/vulnerable/Bad.java": "SQL",
      "java/injection/vulnerable/Missed.java": "nothing",
      "java/injection/safe/Good.java": "nothing",
      "java/injection/safe/Flagged.java": "SQL",
    });
    const cases = listFixtures({ root, language: "java", category: "injection" });
    expect(cases.map((item) => item.relativePath)).toEqual([
      "java/injection/vulnerable/Bad.java",
      "java/injection/vulnerable/Missed.java",
      "java/injection/safe/Flagged.java",
      "java/injection/safe/Good.java",
    ]);
    const report = await runFixtures(cases, (_fixture, source) => (source === "SQL" ? 1 : 0));
    expect(report).toMatchObject({ truePositives: 1, trueNegatives: 1 });
    expect(report.missed.map((item) => item.name)).toEqual(["Missed.java"]);
    expect(report.falsePositives.map((item) => item.name)).toEqual(["Flagged.java"]);
  });
});
