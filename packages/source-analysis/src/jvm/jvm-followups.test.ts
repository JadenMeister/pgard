import { afterAll, describe, expect, it } from "vitest";
import type { RawSourceFinding } from "../finding-factory.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzeJvmTree } from "./analyze-jvm.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

async function run(source: string, path = "A.java") {
  const language = path.endsWith(".kt") ? "kotlin" : "java";
  const outcome = await runtime.parse(language, source);
  if (outcome.status !== "parsed") throw new Error(`not parsed: ${outcome.status}`);
  try {
    return analyzeJvmTree(outcome.tree.rootNode, source, path, language);
  } finally {
    outcome.dispose();
  }
}

type Analysis = Awaited<ReturnType<typeof run>>;
const SQL = "PG-SQL-005";
const PATH = "PG-PATH-002";
const of = (analysis: Analysis, ruleId: string): RawSourceFinding[] =>
  analysis.findings.filter((finding) => finding.ruleId === ruleId);
const java = (imports: string, members: string): string => `${imports}\nclass A {\n${members}\n}\n`;

// ====================================================================== #294

describe("PG-SQL-005: a bare value passed whole to a typed SQL receiver (#294)", () => {
  const JDBC = "import java.sql.*;\n";
  const SPRING = "import org.springframework.jdbc.core.JdbcTemplate;\n";
  const JPA = "import javax.persistence.EntityManager;\n";

  it("reports a bare parameter at low confidence on a typed JDBC Statement", async () => {
    const analysis = await run(
      java(JDBC, "void h(Statement st, String sql) throws Exception { st.executeQuery(sql); }"),
    );
    const found = of(analysis, SQL);
    expect(found).toHaveLength(1);
    expect(found[0]?.confidence).toBe("low");
    expect(found[0]?.evidence).toContain("not followed; inferred");
  });

  it("reports it on JdbcTemplate and EntityManager fields and Kotlin parameters", async () => {
    const template = await run(
      java(
        SPRING,
        "private JdbcTemplate jdbc; Object h(String sql) { return jdbc.queryForList(sql); }",
      ),
    );
    expect(of(template, SQL).map((f) => f.confidence)).toEqual(["low"]);
    const jpa = await run(
      java(JPA, "void h(EntityManager em, String q) { em.createNativeQuery(q); }"),
    );
    expect(of(jpa, SQL).map((f) => f.confidence)).toEqual(["low"]);
    const kotlin = await run(
      `import org.springframework.jdbc.core.JdbcTemplate\nclass K(private val jdbc: JdbcTemplate) {\n fun h(sql: String) = jdbc.queryForList(sql)\n}\n`,
      "K.kt",
    );
    expect(of(kotlin, SQL).map((f) => f.confidence)).toEqual(["low"]);
  });

  it("reports a constant from another file at low confidence", async () => {
    const analysis = await run(
      java(
        JDBC,
        "void h(Statement st) throws Exception { st.executeQuery(Queries.ALL);\nst.executeQuery(ALL_USERS); }",
      ),
    );
    expect(of(analysis, SQL).map((f) => f.confidence)).toEqual(["low", "low"]);
    expect(of(analysis, SQL)[0]?.evidence).toContain("constant defined in another file");
  });

  it("stays silent for an unknown receiver", async () => {
    const analysis = await run(
      java(
        JDBC,
        "void h(Thing st, Runner r, String sql) throws Exception { st.executeQuery(sql); r.execute(sql); r.query(sql); st.execute(sql); }",
      ),
    );
    expect(of(analysis, SQL)).toEqual([]);
  });

  it("stays silent when the type is not the library's (not imported from it)", async () => {
    const analysis = await run(
      java(
        "import com.example.Statement;\n",
        "void h(Statement st, String sql) throws Exception { st.executeQuery(sql); }",
      ),
    );
    expect(of(analysis, SQL)).toEqual([]);
  });

  it("stays silent for a fixed string and for a Connection wrapper", async () => {
    const analysis = await run(
      java(
        JDBC,
        'void h(Statement st, Connection c, String sql) throws Exception { st.executeQuery("select 1"); c.prepareStatement(sql); }',
      ),
    );
    expect(of(analysis, SQL)).toEqual([]);
  });

  it("stays silent for a value that was checked against an allowlist", async () => {
    const analysis = await run(
      java(
        JDBC,
        'void h(Statement st, String sql) throws Exception { if (!ALLOWED.contains(sql)) throw new IllegalArgumentException(); st.executeQuery(sql); } static final java.util.Set<String> ALLOWED = java.util.Set.of("select 1");',
      ),
    );
    expect(of(analysis, SQL)).toEqual([]);
  });

  it("keeps a concatenation with request input high", async () => {
    const analysis = await run(
      java(
        `${JDBC}import javax.servlet.http.*;\n`,
        'void h(Statement st, HttpServletRequest req) throws Exception { st.executeQuery("select * from t where a=" + req.getParameter("a")); }',
      ),
    );
    expect(of(analysis, SQL).map((f) => f.confidence)).toEqual(["high"]);
  });
});

// ====================================================================== #295

describe("PG-PATH-002: typed collection elements, boolean guards, takeIf (#295)", () => {
  const SPRING =
    "import org.springframework.web.bind.annotation.*;\nimport java.io.*;\nimport java.nio.file.*;\n";
  const handler = (body: string): string =>
    java(
      SPRING,
      `final Path base = Paths.get("/srv").toAbsolutePath().normalize();\n@GetMapping("/x") void h(@RequestParam String p) throws Exception {\n${body}\n}`,
    );
  const high = (analysis: Analysis): boolean =>
    of(analysis, PATH).some((finding) => finding.confidence === "high");

  it("does not take the elements of a typed List<LogEntry> for archive entries", async () => {
    const analysis = await run(
      `import java.io.File
import java.util.zip.ZipInputStream
class LogEntry(val name: String)
fun a(logs: List<LogEntry>, dest: File) {
    for (entry in logs) { File(dest, entry.name).mkdirs() }
}
fun b(logs: Array<LogEntry>, dest: File) {
    for (entry in logs) { File(dest, entry.name).mkdirs() }
}
`,
      "K.kt",
    );
    expect(of(analysis, PATH).every((finding) => finding.confidence === "low")).toBe(true);
  });

  it("still takes a loop over an untyped or archive-typed collection for archive entries", async () => {
    const analysis = await run(
      `import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
fun a(zis: ZipInputStream, dest: File) {
    var entry = zis.nextEntry
    File(dest, entry.name).mkdirs()
}
fun b(entries: List<ZipEntry>, dest: File) {
    for (entry in entries) { File(dest, entry.name).mkdirs() }
}
fun c(items: Any, dest: File) {
    for (entry in items) { File(dest, entry.name).mkdirs() }
}
`,
      "K.kt",
    );
    // The last one is known by its name only: medium, as before.
    expect(of(analysis, PATH).map((finding) => finding.confidence)).toEqual([
      "high",
      "high",
      "medium",
    ]);
  });

  const BOOL_GUARDED = [
    "Path x = base.resolve(p).normalize(); boolean ok = x.startsWith(base); if (!ok) throw new SecurityException(); Files.readAllBytes(x);",
    "Path x = base.resolve(p).normalize(); boolean ok = x.startsWith(base); if (ok) { Files.readAllBytes(x); }",
    "Path x = base.resolve(p); boolean ok = x.normalize().startsWith(base); if (!ok) { return; } Files.readAllBytes(x);",
    "Path x = base.resolve(p).normalize(); final boolean inside = x.startsWith(base); if (!inside) throw new SecurityException(); Files.readAllBytes(x);",
  ];
  const BOOL_NOT_GUARDED = [
    // computed, never checked
    "Path x = base.resolve(p).normalize(); boolean ok = x.startsWith(base); Files.readAllBytes(x);",
    // checked, but nothing stops the use
    "Path x = base.resolve(p).normalize(); boolean ok = x.startsWith(base); if (!ok) { System.out.println(); } Files.readAllBytes(x);",
    // the wrong way round
    "Path x = base.resolve(p).normalize(); boolean ok = x.startsWith(base); if (ok) throw new SecurityException(); Files.readAllBytes(x);",
    // the value was replaced after the check was computed
    "Path x = base.resolve(p).normalize(); boolean ok = x.startsWith(base); x = base.resolve(p); if (!ok) throw new SecurityException(); Files.readAllBytes(x);",
    // the variable was reassigned
    "Path x = base.resolve(p).normalize(); boolean ok = x.startsWith(base); ok = true; if (!ok) throw new SecurityException(); Files.readAllBytes(x);",
    // a prefix test on a path that was not resolved
    "Path x = base.resolve(p); boolean ok = x.startsWith(base); if (!ok) throw new SecurityException(); Files.readAllBytes(x);",
    // a condition that is not a path check
    "Path x = base.resolve(p).normalize(); boolean ok = p.length() > 3; if (!ok) throw new SecurityException(); Files.readAllBytes(x);",
  ];

  it.each(BOOL_GUARDED)("recognises a guard kept in a boolean: %s", async (code) => {
    expect(high(await run(handler(code))), code).toBe(false);
  });
  it.each(BOOL_NOT_GUARDED)("keeps the finding for an ineffective boolean: %s", async (code) => {
    expect(high(await run(handler(code))), code).toBe(true);
  });

  it("recognises a guard kept in a Kotlin val", async () => {
    const source = (check: string): string =>
      `import org.springframework.web.bind.annotation.*
import java.io.File
import java.nio.file.*
@RestController
class K {
  val base: Path = Paths.get("/srv")
  @GetMapping("/x")
  fun h(@RequestParam p: String) {
    val x = base.resolve(p).normalize()
    val ok = x.startsWith(base)
${check}
    Files.readAllBytes(x)
  }
}
`;
    expect(high(await run(source("if (!ok) throw SecurityException()"), "K.kt"))).toBe(false);
    expect(high(await run(source(""), "K.kt"))).toBe(true);
    expect(high(await run(source("if (!ok) println()"), "K.kt"))).toBe(true);
  });

  const KT = (use: string): string =>
    `import org.springframework.web.bind.annotation.*
import java.io.File
import java.nio.file.*
@RestController
class K {
  val base: Path = Paths.get("/srv")
  @GetMapping("/x")
  fun h(@RequestParam p: String) {
${use}
  }
}
`;
  const takeIfGuarded = [
    "val x = base.resolve(p).normalize()\n    val safe = x.takeIf { it.startsWith(base) } ?: throw SecurityException()\n    Files.readAllBytes(safe)",
    "val x = base.resolve(p)\n    val safe = x.takeIf { it.normalize().startsWith(base) } ?: throw SecurityException()\n    Files.readAllBytes(safe)",
    "val x = base.resolve(p).normalize()\n    Files.readAllBytes(x.takeIf { p2 -> p2.startsWith(base) } ?: return)",
  ];
  const takeIfNot = [
    // not a path check on the value
    "val x = base.resolve(p).normalize()\n    val safe = x.takeIf { it.toString().length > 3 } ?: throw SecurityException()\n    Files.readAllBytes(safe)",
    // an unresolved path, checked by prefix only
    "val x = base.resolve(p)\n    val safe = x.takeIf { it.startsWith(base) } ?: throw SecurityException()\n    Files.readAllBytes(safe)",
    // the check is on another value
    "val x = base.resolve(p).normalize()\n    val q = base.resolve(p).normalize()\n    val safe = q.takeIf { it.startsWith(base) } ?: throw SecurityException()\n    Files.readAllBytes(x)",
    // takeUnless is the other way round
    "val x = base.resolve(p).normalize()\n    val safe = x.takeUnless { it.startsWith(base) } ?: throw SecurityException()\n    Files.readAllBytes(safe)",
    // no takeIf, only the value
    "val x = base.resolve(p).normalize()\n    Files.readAllBytes(x)",
  ];
  it.each(takeIfGuarded)("recognises a takeIf guard: %s", async (code) => {
    expect(high(await run(KT(code), "K.kt")), code).toBe(false);
  });
  it.each(takeIfNot)("keeps the finding for an ineffective takeIf: %s", async (code) => {
    expect(high(await run(KT(code), "K.kt")), code).toBe(true);
  });
});

// ====================================================================== #286

describe("PG-SQL-005: field values (#286 items 1 and 2)", () => {
  const JDBC = "import java.sql.*;\nimport javax.servlet.http.*;\n";
  const kinds = (analysis: Analysis): string[] => of(analysis, SQL).map((f) => f.confidence);

  it("does not take an array or list constant that a method returns for fixed text", async () => {
    const returned = await run(
      java(
        JDBC,
        'static final String[] COLS = {"a", "b"}; static String[] cols() { return COLS; } void h(Statement st) throws Exception { st.executeQuery("select " + String.join(",", COLS) + " from t"); }',
      ),
    );
    expect(kinds(returned)).toEqual(["low"]);
    const list = await run(
      java(
        JDBC,
        'static final java.util.List<String> COLS = new java.util.ArrayList<>(java.util.List.of("a")); static java.util.List<String> cols() { return COLS; } void h(Statement st) throws Exception { st.executeQuery("select " + String.join(",", COLS) + " from t"); }',
      ),
    );
    expect(kinds(list)).toEqual(["low"]);
  });

  it("keeps an array constant that nothing returns or writes as fixed text", async () => {
    const analysis = await run(
      java(
        JDBC,
        'static final String[] COLS = {"a", "b"}; void h(Statement st) throws Exception { st.executeQuery("select " + String.join(",", COLS) + " from t"); }',
      ),
    );
    expect(of(analysis, SQL)).toEqual([]);
  });

  it("keeps an immutable list constant that a method returns as fixed text", async () => {
    const analysis = await run(
      java(
        JDBC,
        'static final java.util.List<String> COLS = java.util.List.of("a", "b"); static java.util.List<String> cols() { return COLS; } void h(Statement st) throws Exception { st.executeQuery("select " + String.join(",", COLS) + " from t"); }',
      ),
    );
    expect(of(analysis, SQL)).toEqual([]);
  });

  it("does not report a private String field that only holds its literal", async () => {
    const analysis = await run(
      java(
        JDBC,
        'private String table = "users"; void h(Statement st) throws Exception { st.executeQuery("select * from " + table); }',
      ),
    );
    expect(of(analysis, SQL)).toEqual([]);
  });

  const STILL_NOISY = [
    // assigned again
    'private String table = "users"; void set(String t) { this.table = t; } void h(Statement st) throws Exception { st.executeQuery("select * from " + table); }',
    'private String table = "users"; void set(String t) { table = t; } void h(Statement st) throws Exception { st.executeQuery("select * from " + table); }',
    'private String table = "users"; void set(String t) { table += t; } void h(Statement st) throws Exception { st.executeQuery("select * from " + table); }',
    'private String table = "users"; void set(A other, String t) { other.table = t; } void h(Statement st) throws Exception { st.executeQuery("select * from " + table); }',
    // not private: another file can assign it
    'String table = "users"; void h(Statement st) throws Exception { st.executeQuery("select * from " + table); }',
    'public String table = "users"; void h(Statement st) throws Exception { st.executeQuery("select * from " + table); }',
    // no initializer, or one that is not a literal
    'private String table; void h(Statement st) throws Exception { st.executeQuery("select * from " + table); }',
    'private String table = System.getenv("T"); void h(Statement st) throws Exception { st.executeQuery("select * from " + table); }',
    // injected
    '@org.springframework.beans.factory.annotation.Value("${t}") private String table = "users"; void h(Statement st) throws Exception { st.executeQuery("select * from " + table); }',
  ];
  it.each(STILL_NOISY)("keeps the mutable field finding: %s", async (members) => {
    const analysis = await run(java(JDBC, members));
    expect(of(analysis, SQL).length, members).toBeGreaterThan(0);
  });

  it("keeps the finding for a Lombok setter on the class", async () => {
    const analysis = await run(
      java(
        JDBC,
        'private String table = "users"; void h(Statement st) throws Exception { st.executeQuery("select * from " + table); }',
      ).replace("class A", "@lombok.Setter\nclass A"),
    );
    expect(of(analysis, SQL).length).toBeGreaterThan(0);
  });

  it("applies the same to Kotlin private var", async () => {
    const source = (extra: string): string =>
      `import java.sql.Statement\nclass K {\n  private var table = "users"\n${extra}\n  fun h(st: Statement) { st.executeQuery("select * from " + table) }\n}\n`;
    expect(of(await run(source(""), "K.kt"), SQL)).toEqual([]);
    expect(
      of(await run(source("  fun set(t: String) { table = t }"), "K.kt"), SQL).length,
    ).toBeGreaterThan(0);
  });
});

describe("review follow-ups (#286, #295)", () => {
  const JDBC =
    "import org.springframework.jdbc.core.JdbcTemplate;\nimport java.util.*;\nimport org.springframework.web.bind.annotation.*;\n";
  const sql = (analysis: Analysis): number => of(analysis, SQL).length;
  const field = (head: string, extra = ""): string =>
    `${JDBC}${head}\nclass A {\nprivate JdbcTemplate jdbc;\nprivate String table = "users"; ${extra} Object q(@RequestParam String id) { return jdbc.queryForList("select * from " + table + " where id = ?", id); }\n}\n`;

  it("still treats a private literal String as text when nothing assigns it", async () => {
    expect(sql(await run(field("")))).toBe(0);
  });

  it.each([
    [
      "an anonymous class",
      "",
      "void s(String t) { new Thread(new Runnable() { public void run() { table = t; } }).start(); }",
    ],
    ["a local class", "", "void s(String t) { class L { void f() { table = t; } } new L().f(); }"],
    ["Lombok @Builder", "@lombok.Builder", ""],
    ["Lombok @AllArgsConstructor", "@lombok.AllArgsConstructor", ""],
    ["Lombok @Value", "@lombok.Value", ""],
    ["Lombok @With", "@lombok.With", ""],
    ["a JPA entity", "@javax.persistence.Entity", ""],
    ["a mapped superclass", "@jakarta.persistence.MappedSuperclass", ""],
    ["an embeddable", "@javax.persistence.Embeddable", ""],
    ["a Mongo document", "@org.springframework.data.mongodb.core.mapping.Document", ""],
    [
      "Jackson field visibility",
      "@com.fasterxml.jackson.annotation.JsonAutoDetect(fieldVisibility = com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility.ANY)",
      "",
    ],
  ])("keeps the finding when it may be assigned elsewhere: %s", async (_name, head, extra) => {
    expect(sql(await run(field(head, extra)))).toBeGreaterThan(0);
  });

  it("keeps the finding for a field assigned in the nested class of an annotated outer class", async () => {
    const source = `${JDBC}@lombok.Setter\nclass O {\nclass A {\nprivate JdbcTemplate jdbc;\nprivate String table = "users"; Object q(@RequestParam String id) { return jdbc.queryForList("select * from " + table + " where id = ?", id); }\n}\n}\n`;
    expect(sql(await run(source))).toBeGreaterThan(0);
  });

  const K = (members: string): string =>
    `import org.springframework.jdbc.core.JdbcTemplate\nclass K(private val jdbc: JdbcTemplate) {\n${members}\n  fun q() = jdbc.queryForList("select " + COLS.joinToString(",") + " from t")\n  companion object { val COLS = arrayOf("id", "name") }\n}\n`;
  it("does not take a Kotlin arrayOf constant that a function returns for fixed text", async () => {
    expect(sql(await run(K("  fun cols() = COLS"), "K.kt"))).toBeGreaterThan(0);
    expect(
      sql(await run(K("  fun cols(): Array<String> { return COLS }"), "K.kt")),
    ).toBeGreaterThan(0);
    expect(sql(await run(K(""), "K.kt"))).toBe(0);
  });

  const J = (members: string): string =>
    `${JDBC}class A {\nprivate JdbcTemplate jdbc;\nstatic final String[] COLS = {"id", "name"}; ${members} Object q() { return jdbc.queryForList("select " + String.join(",", COLS) + " from t"); }\n}\n`;
  it.each([
    "static String[] cols(boolean b) { return b ? COLS : null; }",
    "static List<String> cols() { return Arrays.asList(COLS); }",
  ])("does not take an array exposed by %s for fixed text", async (members) => {
    expect(sql(await run(J(members)))).toBeGreaterThan(0);
  });

  const KT_ENTRY = (decl: string, loop: string): string =>
    `import java.io.File\nimport java.util.zip.ZipEntry\n${decl}\n${loop}\n`;
  it("keeps a class that extends an archive entry, and a type parameter, as possible entries", async () => {
    const sub = await run(
      KT_ENTRY(
        "class Item(n: String) : ZipEntry(n)",
        "fun b(entries: List<Item>, dest: File) { for (entry in entries) { File(dest, entry.name).mkdirs() } }",
      ),
      "K.kt",
    );
    expect(of(sub, PATH).map((f) => f.confidence)).toEqual(["high"]);
    const generic = await run(
      KT_ENTRY(
        "",
        "fun <T> b(entries: List<T>, dest: File) { for (entry in entries) { File(dest, (entry as ZipEntry).name).mkdirs() } }",
      ),
      "K.kt",
    );
    expect(of(generic, PATH).length).toBeGreaterThan(0);
    const other = await run(
      KT_ENTRY(
        "class Row(val name: String)",
        "fun b(entries: List<Row>, dest: File) { for (entry in entries) { File(dest, entry.name).mkdirs() } }",
      ),
      "K.kt",
    );
    expect(of(other, PATH).every((f) => f.confidence === "low")).toBe(true);
  });
});
