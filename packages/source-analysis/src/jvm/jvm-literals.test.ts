import { afterAll, describe, expect, it } from "vitest";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzeJvmTree, assignCountsOf } from "./analyze-jvm.js";
import { scaled } from "../../../../tests/support/timing.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

async function sqlFindings(source: string, path: string): Promise<number> {
  const language = path.endsWith(".kt") ? "kotlin" : "java";
  const outcome = await runtime.parse(language, source);
  if (outcome.status !== "parsed") throw new Error(`not parsed: ${outcome.status}`);
  try {
    return analyzeJvmTree(outcome.tree.rootNode, source, path, language).findings.filter(
      (finding) => finding.ruleId === "PG-SQL-005",
    ).length;
  } finally {
    outcome.dispose();
  }
}

const JDBC =
  "import org.springframework.jdbc.core.JdbcTemplate;\nimport java.util.*;\nimport org.springframework.web.bind.annotation.*;\n";
const java = (members: string): string =>
  `${JDBC}class A {\nprivate JdbcTemplate jdbc;\nprivate String table = "users";\n${members}\nObject q(@RequestParam String id) { return jdbc.queryForList("select * from " + table + " where id = ?", id); }\n}\n`;
const kt = (members: string): string =>
  `import org.springframework.jdbc.core.JdbcTemplate\nclass K(private val jdbc: JdbcTemplate) {\n  private var table: String = "users"\n${members}\n  fun q() = jdbc.queryForList("select * from " + table + " where id = ?", "1")\n}\n`;
const TB = '"'.repeat(3);

describe("string and character literals do not hide an assignment", () => {
  it("keeps the finding when a Java text block holds an escaped delimiter before an assignment", async () => {
    const hidden = `String d = ${TB}\nx \\${TB} y\n${TB}; void s(String t) { table = t; } String e = ${TB}\nz\n${TB};`;
    expect(await sqlFindings(java(hidden), "A.java")).toBeGreaterThan(0);
  });

  it("still ignores an equals sign inside a Java text block", async () => {
    const block = `String d = ${TB}\ntable = x \\${TB} y\n${TB};`;
    expect(await sqlFindings(java(block), "A.java")).toBe(0);
  });

  it("keeps the finding after a Kotlin quote character inside a template", async () => {
    const members = `  fun a(t: String) { val s = "\${'"'}"; table = t }`;
    expect(await sqlFindings(kt(members), "K.kt")).toBeGreaterThan(0);
  });

  it("still ignores an equals sign inside a character literal and a Kotlin raw string", async () => {
    const members = `  val c = '='\n  val r = ${TB}table = x\\${TB}`;
    expect(await sqlFindings(kt(members), "K.kt")).toBe(0);
  });

  it("scans long runs of quotes and backslashes in linear time", () => {
    for (const input of [
      `${TB}${"\\".repeat(200_000)}${TB}x=1`,
      `x = ${`\\${TB}`.repeat(60_000)}`,
      "'".repeat(300_000),
      `${TB} \\${TB}`.repeat(50_000),
    ]) {
      const startedAt = performance.now();
      assignCountsOf(input);
      expect(performance.now() - startedAt).toBeLessThan(scaled(1500));
    }
  });
});
