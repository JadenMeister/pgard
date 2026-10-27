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
    for (const area of ["source:java", "source:kotlin"]) {
      const entry = output.coverage.find((item) => item.area === area);
      expect(entry, area).toMatchObject({
        status: "completed",
        ruleIds: ["PG-SQL-005", "PG-XSS-004", "PG-SSRF-002", "PG-CMD-003", "PG-PATH-002"],
      });
    }
    // Mapper XML is read for SQL only; the command and path rules do not claim it.
    expect(output.coverage.find((item) => item.area === "source:mybatis")).toMatchObject({
      status: "completed",
      ruleIds: ["PG-SQL-005"],
    });
    expect(output.coverage.find((item) => item.area === "source:java")?.note).toMatch(
      /^1 Java file\(s\); frameworks: Spring; .*SQL injection \(PG-SQL-005\), OS command execution \(PG-CMD-003\), path traversal \(PG-PATH-002\), XSS \(PG-XSS-004[^)]*\) and SSRF \(PG-SSRF-002\)/,
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

  it("marks the area partial when a SQL call is in an anonymous class, a local class or a local function", async () => {
    const anonymous = `import org.springframework.jdbc.core.JdbcTemplate;
class A { JdbcTemplate jdbc; void f(String q) {
  Runnable r = new Runnable() { public void run() { jdbc.execute("DELETE FROM t WHERE n = '" + q + "'"); } };
} }
`;
    const local = `import org.springframework.jdbc.core.JdbcTemplate;
class B { JdbcTemplate jdbc; void f(String q) {
  class Local { void go() { jdbc.execute("DELETE FROM t WHERE n = '" + q + "'"); } }
} }
`;
    const kotlinLocal = `import org.springframework.jdbc.core.JdbcTemplate
class C(private val jdbc: JdbcTemplate) { fun f(q: String) {
  fun inner() { jdbc.execute("DELETE FROM t WHERE n = '$q'") }
  inner()
} }
`;
    const java = await scanSourceCode(project({ "A.java": anonymous, "B.java": local }));
    const javaEntry = java.coverage.find((item) => item.area === "source:java");
    expect(javaEntry?.status).toBe("partial");
    expect(javaEntry?.note).toContain("anonymous class bodies");
    expect(javaEntry?.note).toContain("local class bodies");
    const kt = await scanSourceCode(project({ "C.kt": kotlinLocal }));
    const ktEntry = kt.coverage.find((item) => item.area === "source:kotlin");
    expect(ktEntry?.status).toBe("partial");
    expect(ktEntry?.note).toContain("local function bodies");
  });

  it("an anonymous class without a SQL-looking call does not make the area partial", async () => {
    const output = await scanSourceCode(
      project({
        "A.java": "class A { Runnable r = new Runnable() { public void run() { go(); } }; }\n",
      }),
    );
    expect(output.coverage.find((item) => item.area === "source:java")?.status).toBe("completed");
  });

  it("lists jOOQ, Exposed, Room and MyBatis providers as partial, not tested areas", async () => {
    const output = await scanSourceCode(
      project({
        "A.java": "import org.jooq.DSLContext;\nclass A {}\n",
        "B.kt": "import org.jetbrains.exposed.sql.transactions.transaction\nclass B\n",
        "C.kt": "import androidx.room.Query\nclass C\n",
        "D.java":
          'import org.apache.ibatis.annotations.*;\ninterface D { @SelectProvider(type = P.class, method = "m") Object f(); }\n',
      }),
    );
    for (const area of [
      "source:orm:jooq",
      "source:orm:exposed",
      "source:orm:room",
      "source:orm:mybatis-sql-providers",
    ]) {
      const entry = output.coverage.find((item) => item.area === area);
      expect(entry?.status, area).toBe("partial");
      expect(entry?.note, area).toContain("not a safe result");
    }
  });

  it("lists process and file libraries the command and path rules do not follow as partial areas", async () => {
    const output = await scanSourceCode(
      project({
        "A.java": "import org.zeroturnaround.exec.ProcessExecutor;\nclass A {}\n",
        "B.kt": "import com.zaxxer.nuprocess.NuProcessBuilder\nclass B\n",
        "C.kt": "import okio.FileSystem\nclass C\n",
        "D.java": "import io.vertx.core.file.FileSystem;\nclass D {}\n",
      }),
    );
    for (const [area, label] of [
      ["source:process:zt-exec", "zt-exec"],
      ["source:process:nuprocess", "NuProcess"],
      ["source:file:okio", "Okio"],
      ["source:file:vert-x-file-system", "Vert.x file system"],
    ] as const) {
      const entry = output.coverage.find((item) => item.area === area);
      expect(entry?.status, area).toBe("partial");
      expect(entry?.ruleIds, area).toEqual(
        area.startsWith("source:process") ? ["PG-CMD-003"] : ["PG-PATH-002"],
      );
      expect(entry?.note, area).toContain(label);
      expect(entry?.note, area).toContain("not a safe result");
    }
    // The Java and Kotlin areas themselves still completed: nothing in them was skipped.
    expect(output.coverage.find((item) => item.area === "source:java")?.status).toBe("completed");
  });

  it("reports command and path findings with per-area rule statistics", async () => {
    const java = `import java.io.*;
import javax.servlet.http.*;
class A {
  void f(HttpServletRequest r) throws Exception {
    Runtime.getRuntime().exec("ls " + r.getParameter("d"));
    new File("/srv/" + r.getParameter("n")).delete();
  }
}
`;
    const kotlin = `import java.io.File
import javax.servlet.http.HttpServletRequest
fun f(r: HttpServletRequest) {
    ProcessBuilder("sh", "-c", "ls " + r.getParameter("d")).start()
    File("/srv", r.getParameter("n")).readText()
}
`;
    const output = await scanSourceCode(project({ "A.java": java, "B.kt": kotlin }));
    for (const ruleId of ["PG-CMD-003", "PG-PATH-002"]) {
      expect(output.findings.filter((finding) => finding.ruleId === ruleId)).toHaveLength(2);
      for (const area of ["source:java", "source:kotlin"]) {
        expect(
          output.ruleStats?.find((row) => row.ruleId === ruleId && row.area === area),
        ).toMatchObject({
          status: "completed",
          findings: 1,
        });
      }
    }
    const [critical] = output.findings.filter((finding) => finding.ruleId === "PG-CMD-003");
    expect(critical).toMatchObject({ severity: "critical", category: "command_execution" });
    expect(critical?.references).toMatchObject({ cwe: ["CWE-78"], owasp: ["A05:2025"] });
    const [path] = output.findings.filter((finding) => finding.ruleId === "PG-PATH-002");
    expect(path).toMatchObject({ severity: "high", category: "file_handling" });
    expect(path?.references).toMatchObject({ cwe: ["CWE-22"], owasp: ["A01:2025"] });
  });

  it("marks the area partial when a command or file call is in an anonymous class or a local function", async () => {
    const java = `class A { void f(String p) {
  Runnable r = new Runnable() { public void run() { try { Runtime.getRuntime().exec("x " + p); } catch (Exception e) {} } };
} }
`;
    const kotlin = `import java.io.File
class K { fun f(p: String) {
  fun inner() { File(p).delete() }
  inner()
} }
`;
    const output = await scanSourceCode(project({ "A.java": java, "K.kt": kotlin }));
    const javaEntry = output.coverage.find((item) => item.area === "source:java");
    expect(javaEntry?.status).toBe("partial");
    expect(javaEntry?.note).toContain(
      "SQL, command, file-path, response-writing or URL calls inside anonymous class bodies",
    );
    const kotlinEntry = output.coverage.find((item) => item.area === "source:kotlin");
    expect(kotlinEntry?.status).toBe("partial");
    expect(kotlinEntry?.note).toContain("local function bodies");
  });

  it("marks the MyBatis area partial for a statement that is never closed", async () => {
    const output = await scanSourceCode(
      project({
        "M.xml": `<mapper namespace="a.B">\n<select id="x">SELECT \${c} FROM t\n</mapper>\n`,
      }),
    );
    const entry = output.coverage.find((item) => item.area === "source:mybatis");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("never closed");
  });

  it("does not read XML under res/ or target/, nor a mybatis-config", async () => {
    const output = await scanSourceCode(
      project({
        "app/src/main/res/layout/M.xml": MAPPER,
        "target/classes/M.xml": MAPPER,
        "mybatis-config.xml": `<configuration><mappers><mapper resource="M.xml"/></mappers></configuration>`,
      }),
    );
    expect(output.findings.filter((f) => f.ruleId === "PG-SQL-005")).toEqual([]);
    expect(output.coverage.some((item) => item.area === "source:mybatis")).toBe(false);
  });

  it("marks the area partial, naming the file, when the parser could not recover from a syntax error", async () => {
    const source = `import org.springframework.jdbc.core.JdbcTemplate
class C(private val jdbc: JdbcTemplate) {
  fun r(s: String): Any {
    var where = "id"
    val q = { jdbc.queryForList("SELECT * FROM t$where") }
    where = s
    return q()
  }
}
`;
    const output = await scanSourceCode(project({ "Bad.kt": source }));
    const entry = output.coverage.find((item) => item.area === "source:kotlin");
    expect(entry?.status).toBe("partial");
    expect(entry?.note).toContain("syntax errors");
    expect(entry?.note).toContain("Bad.kt");
  });

  it("stops when the scan is aborted", async () => {
    const controller = new AbortController();
    controller.abort(new Error("stop"));
    await expect(
      scanSourceCode(project({ "A.java": JAVA }), { signal: controller.signal }),
    ).rejects.toThrow("stop");
  });
});
