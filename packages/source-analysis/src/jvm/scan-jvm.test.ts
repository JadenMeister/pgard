import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { scanSourceCode } from "../scan-source.js";

const roots: string[] = [];
function project(files: Record<string, string>): string {
  const root = realpathSync(mkdtempSync(path.join(tmpdir(), "pgard-jvm-")));
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

const JAVA = `import java.sql.*;
import javax.servlet.http.*;
class A {
  void f(Statement st, HttpServletRequest r) throws Exception {
    st.executeQuery("SELECT * FROM t WHERE a = " + r.getParameter("a"));
  }
}
`;
const KOTLIN = `import java.sql.Connection
fun f(c: Connection, call: ApplicationCall) {
    c.createStatement().executeQuery("SELECT * FROM t WHERE a = " + call.parameters["a"])
}
`;
const MAPPER = `<mapper namespace="a.B">
  <select id="x">SELECT * FROM t ORDER BY \${col}</select>
</mapper>
`;

describe("scanSourceCode with Java, Kotlin and MyBatis", () => {
  it("reports findings and per-area coverage for the rule", async () => {
    const root = project({
      "src/main/java/A.java": JAVA,
      "src/main/kotlin/B.kt": KOTLIN,
      "src/main/resources/mapper/UserMapper.xml": MAPPER,
      "pom.xml": "<project><groupId>org.springframework.boot</groupId></project>",
    });
    const output = await scanSourceCode(root);
    const sql = output.findings.filter((finding) => finding.ruleId === "PG-SQL-005");
    expect(sql.map((finding) => finding.location.path).sort()).toEqual([
      "src/main/java/A.java",
      "src/main/kotlin/B.kt",
      "src/main/resources/mapper/UserMapper.xml",
    ]);
    for (const area of ["source:java", "source:kotlin", "source:mybatis"]) {
      const entry = output.coverage.find((item) => item.area === area);
      expect(entry, area).toMatchObject({ status: "completed", ruleIds: ["PG-SQL-005"] });
    }
    expect(output.coverage.find((item) => item.area === "source:java")?.note).toMatch(
      /^1 Java file\(s\); frameworks: Spring; .*SQL injection only/,
    );
    expect(output.coverage.find((item) => item.area === "source:mybatis")?.note).toMatch(
      /^1 MyBatis mapper XML file\(s\)/,
    );
    for (const area of ["source:java", "source:kotlin", "source:mybatis"]) {
      expect(output.ruleStats?.find((row) => row.area === area)).toMatchObject({
        ruleId: "PG-SQL-005",
        status: "completed",
        findings: 1,
      });
    }
    // "detected, no rules yet" is gone for Java and Kotlin.
    expect(output.coverage.some((item) => /no rules yet/.test(item.note ?? ""))).toBe(false);
  });

  it("does not list a language or MyBatis area when there are no such files", async () => {
    const output = await scanSourceCode(project({ "a.js": "console.log(1)\n" }));
    for (const area of ["source:java", "source:kotlin", "source:mybatis"]) {
      expect(
        output.coverage.some((item) => item.area === area),
        area,
      ).toBe(false);
    }
  });

  it("ignores XML that is not a mapper and pom.xml", async () => {
    const output = await scanSourceCode(
      project({
        "pom.xml": "<project><name>${x}</name></project>",
        "config/app.xml": "<config><v>${home}</v></config>",
        "A.java": "class A {}\n",
      }),
    );
    expect(output.findings.filter((finding) => finding.ruleId === "PG-SQL-005")).toEqual([]);
    expect(output.coverage.some((item) => item.area === "source:mybatis")).toBe(false);
  });

  it("leaves excluded Java files and mapper XML out and says so", async () => {
    const root = project({
      "A.java": JAVA,
      "gen/B.java": JAVA,
      "gen/M.xml": MAPPER,
    });
    const output = await scanSourceCode(root, {
      projectConfig: {
        version: 1,
        exclude: ["gen/**"],
        testDirectories: [],
        suppressions: [],
      } as never,
    });
    const paths = output.findings
      .filter((f) => f.ruleId === "PG-SQL-005")
      .map((f) => f.location.path);
    expect(paths).toEqual(["A.java"]);
    expect(output.coverage.find((item) => item.area === "source:config-excluded")?.note).toMatch(
      /^2 /,
    );
  });

  it("marks the area partial when a file is too large to parse", async () => {
    const big = `class Big {\n${"// padding padding padding padding padding padding\n".repeat(25_000)}}\n`;
    expect(big.length).toBeGreaterThan(1024 * 1024);
    const output = await scanSourceCode(project({ "Big.java": big, "A.java": JAVA }));
    const entry = output.coverage.find((item) => item.area === "source:java");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("Big.java");
    expect(entry?.note).toContain("not a safe result");
    // The other file was still analyzed.
    expect(output.findings.some((f) => f.location.path === "A.java")).toBe(true);
  });

  it("marks the area partial when a file nests too deeply to analyze in full", async () => {
    const deep = `class A { void f(boolean a) { ${"if (a) { ".repeat(400)}${" }".repeat(400)} } }\n`;
    const output = await scanSourceCode(project({ "A.java": deep }));
    const entry = output.coverage.find((item) => item.area === "source:java");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("nested too deeply");
  });

  it("counts files that hit the per-file cap", async () => {
    const methods = Array.from(
      { length: 40 },
      (_, i) =>
        `void m${i}(Statement st, HttpServletRequest r) throws Exception { st.executeQuery("SELECT ${i} WHERE a = " + r.getParameter("a")); }`,
    ).join("\n");
    const output = await scanSourceCode(
      project({
        "A.java": `import java.sql.*;\nimport javax.servlet.http.*;\nclass A {\n${methods}\n}\n`,
      }),
    );
    const entry = output.coverage.find((item) => item.area === "source:java");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("per-file finding cap");
    expect(output.findings.filter((f) => f.ruleId === "PG-SQL-005")).toHaveLength(25);
  });

  it("stops when the scan is aborted", async () => {
    const controller = new AbortController();
    controller.abort(new Error("stop"));
    await expect(
      scanSourceCode(project({ "A.java": JAVA }), { signal: controller.signal }),
    ).rejects.toThrow("stop");
  });
});
