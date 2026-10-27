import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanSourceCode } from "../scan-source.js";
import { analyzeSpringConfig, parseProperties, parseYaml } from "./spring-config.js";

const roots: string[] = [];
function project(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-springcfg-")));
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

const flat = (parsed: ReturnType<typeof parseYaml>) =>
  Object.fromEntries(parsed.documents.flat().map((entry) => [entry.key, entry.value]));

describe("properties reader", () => {
  it("reads separators, comments, continuations and list indexes", () => {
    const parsed = parseProperties(
      "# comment\n! other\na.b=1\nc.d : two\ne.f three\ng.h=a,\\\n  b\nlist[0]=x\nlist[1]=y\n",
    );
    expect(parsed.malformedLine).toBeNull();
    expect(parsed.documents[0]?.map((entry) => [entry.key, entry.value, entry.line])).toEqual([
      ["a.b", "1", 3],
      ["c.d", "two", 4],
      ["e.f", "three", 5],
      ["g.h", "a,b", 6],
      ["list", "x", 8],
      ["list", "y", 9],
    ]);
  });

  it("flags a malformed unicode escape", () => {
    expect(parseProperties("a=\\u12\n").malformedLine).toBe(1);
  });
});

describe("YAML reader", () => {
  it("reads nested maps, dotted keys, quoted scalars, comments and lists", () => {
    const parsed = parseYaml(
      [
        "server:",
        "  servlet:",
        "    session:",
        "      cookie:",
        "        http-only: false # note",
        '        name: "A: B"',
        "a.b.c: 'x'",
        "management:",
        "  endpoints:",
        "    web:",
        "      exposure:",
        "        include:",
        "          - health",
        '          - "*"',
        "flow: [a, 'b']",
      ].join("\n"),
    );
    expect(parsed.malformedLine).toBeNull();
    expect(flat(parsed)).toMatchObject({
      "server.servlet.session.cookie.http-only": "false",
      "server.servlet.session.cookie.name": "A: B",
      "a.b.c": "x",
      "management.endpoints.web.exposure.include": "health,*",
      flow: "a,b",
    });
  });

  it("splits documents and skips block scalars", () => {
    const parsed = parseYaml("a: |\n  text: not a key\n  more\nb: 1\n---\nc: 2\n");
    expect(parsed.malformedLine).toBeNull();
    expect(parsed.documents).toHaveLength(2);
    expect(flat({ documents: [parsed.documents[0] ?? []], malformedLine: null })).toMatchObject({
      b: "1",
    });
  });

  it("flags tabs, unbalanced quotes and multi-line flow maps", () => {
    expect(parseYaml("a:\n\tb: 1\n").malformedLine).toBe(2);
    expect(parseYaml('a: "open\n').malformedLine).toBe(1);
    expect(parseYaml("a: {b: 1,\n  c: 2}\n").malformedLine).toBe(1);
    expect(parseYaml("just words here\n").malformedLine).toBe(1);
  });
});

describe("Spring configuration rules", () => {
  const rulesOf = (text: string, name: string, kind: "properties" | "yaml") =>
    analyzeSpringConfig(text, name, kind).findings.map(
      (finding) => `${finding.ruleId}:${finding.line}:${finding.confidence}`,
    );

  it("reports http-only and secure set to false, relaxed key names included", () => {
    expect(
      rulesOf(
        "server.servlet.session.cookie.httpOnly=false\nserver.session.cookie.secure=false\n",
        "application.properties",
        "properties",
      ),
    ).toEqual(["PG-COOKIE-001:1:medium", "PG-COOKIE-001:2:medium"]);
  });

  it("is silent for true, for placeholders without a default and for same-site", () => {
    expect(
      rulesOf(
        "server.servlet.session.cookie.http-only=true\nserver.servlet.session.cookie.secure=${S}\nserver.servlet.session.cookie.same-site=none\n",
        "application.properties",
        "properties",
      ),
    ).toEqual([]);
  });

  it("demotes a development profile and a placeholder with a false default", () => {
    expect(
      rulesOf(
        "server.servlet.session.cookie.secure=false\n",
        "src/application-dev.properties",
        "properties",
      ),
    ).toEqual(["PG-COOKIE-001:1:low"]);
    expect(
      rulesOf(
        "server.servlet.session.cookie.secure=${S:false}\n",
        "application.properties",
        "properties",
      ),
    ).toEqual(["PG-COOKIE-001:1:low"]);
    expect(
      rulesOf(
        "a: 1\n---\nspring.config.activate.on-profile: dev\nserver.servlet.session.cookie.secure: false\n",
        "application.yml",
        "yaml",
      ),
    ).toEqual(["PG-COOKIE-001:4:low"]);
    expect(
      rulesOf(
        "server.servlet.session.cookie.secure=false\n",
        "application-prod.properties",
        "properties",
      ),
    ).toEqual(["PG-COOKIE-001:1:medium"]);
  });

  it("reports security debug logging as low severity", () => {
    const [finding] = analyzeSpringConfig(
      "logging.level.org.springframework.security=DEBUG\n",
      "application.properties",
      "properties",
    ).findings;
    expect(finding).toMatchObject({ ruleId: "PG-CONF-001", severity: "low" });
  });

  it("caps the findings of one file", () => {
    const text = Array.from(
      { length: 40 },
      () => "server.servlet.session.cookie.secure=false",
    ).join("\n");
    const result = analyzeSpringConfig(text, "application.properties", "properties");
    expect(result.findings).toHaveLength(25);
    expect(result.capped).toBe(true);
  });
});

describe("scanSourceCode and Spring configuration files", () => {
  const JAVA = "class A {}\n";

  it("reads the files in a Java project and lists the area", async () => {
    const root = project({
      "pom.xml": "<project/>",
      "src/main/resources/application.properties": "server.servlet.session.cookie.secure=false\n",
      "src/main/resources/application-prod.yml":
        "server:\n  servlet:\n    session:\n      cookie:\n        http-only: false\n",
    });
    const output = await scanSourceCode(root);
    const cookie = output.findings.filter((finding) => finding.ruleId === "PG-COOKIE-001");
    expect(cookie.map((finding) => finding.location.path).sort()).toEqual([
      "src/main/resources/application-prod.yml",
      "src/main/resources/application.properties",
    ]);
    expect(output.coverage.find((entry) => entry.area === "source:jvm-config")).toMatchObject({
      status: "completed",
      ruleIds: ["PG-COOKIE-001", "PG-CONF-001"],
    });
  });

  it("does not read them outside a JVM project", async () => {
    const root = project({
      "package.json": "{}",
      "application.properties": "server.servlet.session.cookie.secure=false\n",
    });
    const output = await scanSourceCode(root);
    expect(output.findings).toEqual([]);
    expect(output.coverage.some((entry) => entry.area === "source:jvm-config")).toBe(false);
  });

  it("reports a malformed and an oversized file as partial", async () => {
    const root = project({
      "A.java": JAVA,
      "application.yml": "a:\n\tb: 1\n",
      "application-big.properties": `a=${"x".repeat(300 * 1024)}\n`,
    });
    const output = await scanSourceCode(root);
    const entry = output.coverage.find((item) => item.area === "source:jvm-config");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("could not parse");
    expect(entry?.note).toContain("over 256 KiB");
  });

  it("reports Actuator exposure only when no Spring Security is shown", async () => {
    const exposure = "management.endpoints.web.exposure.include=*\n";
    const open = await scanSourceCode(
      project({ "A.java": JAVA, "application.properties": exposure }),
    );
    const found = open.findings.filter((finding) => finding.ruleId === "PG-CONF-001");
    expect(found).toHaveLength(1);
    expect(found[0]).toMatchObject({ severity: "low", confidence: "low" });
    expect(found[0]?.evidence).toContain("inferred");

    const withImport = await scanSourceCode(
      project({
        "A.java": "import org.springframework.security.core.Authentication;\nclass A {}\n",
        "application.properties": exposure,
      }),
    );
    expect(withImport.findings.filter((finding) => finding.ruleId === "PG-CONF-001")).toEqual([]);

    const withDependency = await scanSourceCode(
      project({
        "pom.xml": "<project><artifactId>spring-boot-starter-security</artifactId></project>",
        "application.properties": exposure,
      }),
    );
    expect(withDependency.findings.filter((finding) => finding.ruleId === "PG-CONF-001")).toEqual(
      [],
    );
  });

  it("leaves out files the project excludes", async () => {
    const root = project({
      "pom.xml": "<project/>",
      "legacy/application.properties": "server.servlet.session.cookie.secure=false\n",
    });
    const output = await scanSourceCode(root, {
      projectConfig: { version: 1, exclude: ["legacy"], testDirectories: [], suppressions: [] },
    });
    expect(output.findings).toEqual([]);
  });

  it("the Spring Security chain forms that are not followed make the Java area partial", async () => {
    const root = project({
      "C.java":
        "import org.springframework.security.config.annotation.web.builders.HttpSecurity;\nclass C {\n  void f(HttpSecurity http) throws Exception {\n    http.apply(new MyDsl());\n    http.csrf(c -> c.disable());\n  }\n}\n",
    });
    const output = await scanSourceCode(root);
    const entry = output.coverage.find((item) => item.area === "source:java");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("Spring Security filter chain");
  });
});
