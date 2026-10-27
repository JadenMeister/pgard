import { afterAll, describe, expect, it } from "vitest";
import type { RawSourceFinding } from "../finding-factory.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzeJvmTree, analyzeMybatisXml } from "./analyze-jvm.js";

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

type Kind = "none" | "confirmed" | "suspected" | "untraced" | "inferred";

/** What the rule said, in the words of the design: strong, untraced (low) or inferred (low). */
function kindOf(findings: RawSourceFinding[]): Kind {
  if (findings.length === 0) return "none";
  const finding = findings[0] as RawSourceFinding;
  if (finding.confidence === "low") {
    return finding.evidence.endsWith("; inferred") ? "inferred" : "untraced";
  }
  return finding.status === "confirmed" ? "confirmed" : "suspected";
}

const JDBC_IMPORTS = "import java.sql.*;\nimport javax.servlet.http.*;\n";
const SPRING_IMPORTS =
  "import org.springframework.jdbc.core.*;\nimport org.springframework.web.bind.annotation.*;\n";
const JPA_IMPORTS =
  "import javax.persistence.*;\nimport org.springframework.web.bind.annotation.*;\n";

const java = (imports: string, members: string): string => `${imports}\nclass A {\n${members}\n}\n`;
const kotlin = (imports: string, body: string): string => `package a\n${imports}\n${body}\n`;

interface Case {
  name: string;
  source: string;
  expected: Kind;
  path?: string;
}

const CASES: Case[] = [
  // ---- JDBC sinks ----
  {
    name: "Statement.executeQuery with a concatenated request parameter",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest request) throws Exception {
        st.executeQuery("SELECT * FROM t WHERE a = '" + request.getParameter("a") + "'");
      }`,
    ),
    expected: "confirmed",
  },
  {
    name: "Statement.execute and executeUpdate",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest r) throws Exception {
        String id = r.getParameter("id");
        st.execute("DELETE FROM t WHERE id = " + id);
        st.executeUpdate("UPDATE t SET a = 1 WHERE id = " + id);
      }`,
    ),
    expected: "suspected",
  },
  {
    name: "Statement.addBatch",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest r) throws Exception {
        st.addBatch("INSERT INTO t VALUES ('" + r.getHeader("X-A") + "')");
      }`,
    ),
    expected: "confirmed",
  },
  {
    name: "Connection.prepareStatement with a concatenated string",
    source: java(
      JDBC_IMPORTS,
      `void f(Connection c, HttpServletRequest r) throws Exception {
        c.prepareStatement("SELECT * FROM t WHERE a = " + r.getQueryString());
      }`,
    ),
    expected: "confirmed",
  },
  {
    name: "Connection.prepareCall",
    source: java(
      JDBC_IMPORTS,
      `void f(Connection c, HttpServletRequest r) throws Exception {
        c.prepareCall("{call p(" + r.getParameter("x") + ")}");
      }`,
    ),
    expected: "confirmed",
  },
  {
    name: "prepareStatement with ? placeholders is safe",
    source: java(
      JDBC_IMPORTS,
      `void f(Connection c, HttpServletRequest r) throws Exception {
        PreparedStatement ps = c.prepareStatement("SELECT * FROM t WHERE a = ?");
        ps.setString(1, r.getParameter("a"));
        ps.executeQuery();
      }`,
    ),
    expected: "none",
  },
  // ---- Spring JDBC ----
  {
    name: "JdbcTemplate query/queryForObject/queryForList/update/execute",
    source: java(
      SPRING_IMPORTS,
      `JdbcTemplate jdbc;
      @GetMapping("/x") void f(@RequestParam String n) {
        jdbc.query("SELECT * FROM t WHERE n = '" + n + "'", (rs, i) -> 1);
      }
      @GetMapping("/y") void g(@RequestParam String n) {
        jdbc.queryForObject("SELECT 1 FROM t WHERE n = '" + n + "'", Integer.class);
      }
      @GetMapping("/z") void h(@RequestParam String n) {
        jdbc.queryForList("SELECT n FROM t WHERE n = '" + n + "'");
      }
      @GetMapping("/u") void i(@RequestParam String n) {
        jdbc.update("UPDATE t SET n = '" + n + "'");
      }
      @GetMapping("/e") void j(@RequestParam String n) {
        jdbc.execute("DROP TABLE " + n);
      }`,
    ),
    expected: "confirmed",
  },
  {
    name: "NamedParameterJdbcTemplate with a built SQL string",
    source: java(
      "import org.springframework.jdbc.core.namedparam.*;\nimport org.springframework.web.bind.annotation.*;\n",
      `NamedParameterJdbcTemplate named;
      @GetMapping("/x") void f(@RequestParam String col) {
        named.query("SELECT * FROM t ORDER BY " + col, (rs, i) -> 1);
      }`,
    ),
    expected: "confirmed",
  },
  {
    name: "JdbcTemplate with placeholders is safe",
    source: java(
      SPRING_IMPORTS,
      `JdbcTemplate jdbc;
      @GetMapping("/x") void f(@RequestParam String n) {
        jdbc.query("SELECT * FROM t WHERE n = ?", (rs, i) -> 1, n);
      }`,
    ),
    expected: "none",
  },
  {
    name: "a PreparedStatementCreator lambda is followed to its prepareStatement",
    source: java(
      SPRING_IMPORTS + "import java.sql.*;\n",
      `JdbcTemplate jdbc;
      @GetMapping("/x") void f(@RequestParam String n) {
        jdbc.update(con -> con.prepareStatement("DELETE FROM t WHERE n = '" + n + "'"));
      }`,
    ),
    expected: "confirmed",
  },
  {
    name: "update(entity) on a DAO is not a SQL call",
    source: java(
      SPRING_IMPORTS,
      `UserDao userDao;
      @PostMapping("/x") void f(@RequestBody User user) {
        userDao.update(user);
      }`,
    ),
    expected: "none",
  },
  // ---- JPA / Hibernate ----
  {
    name: "EntityManager.createQuery with concatenation",
    source: java(
      JPA_IMPORTS,
      `EntityManager em;
      @GetMapping("/x") void f(@RequestParam String n) {
        em.createQuery("select u from User u where u.name = '" + n + "'");
      }`,
    ),
    expected: "confirmed",
  },
  {
    name: "createNativeQuery and Hibernate createSQLQuery",
    source: java(
      "import javax.persistence.*;\nimport org.hibernate.Session;\nimport javax.servlet.http.*;\n",
      `EntityManager em; Session session;
      void f(HttpServletRequest r) {
        em.createNativeQuery("SELECT * FROM t WHERE a = " + r.getParameter("a"));
        session.createSQLQuery("SELECT * FROM t WHERE a = " + r.getParameter("b"));
      }`,
    ),
    expected: "confirmed",
  },
  {
    name: "createQuery with a named parameter is safe",
    source: java(
      JPA_IMPORTS,
      `EntityManager em;
      @GetMapping("/x") void f(@RequestParam String n) {
        em.createQuery("select u from User u where u.name = :n").setParameter("n", n);
        em.createNativeQuery("SELECT * FROM t WHERE a = ?1").setParameter(1, n);
      }`,
    ),
    expected: "none",
  },
  {
    name: "createQuery(CriteriaQuery) is not SQL text",
    source: java(
      JPA_IMPORTS,
      `EntityManager em;
      @GetMapping("/x") void f(@RequestParam String n) {
        em.createQuery(buildCriteria(n));
      }`,
    ),
    expected: "none",
  },
  // ---- sources ----
  {
    name: "@RequestHeader and @CookieValue",
    source: java(
      SPRING_IMPORTS,
      `JdbcTemplate jdbc;
      @GetMapping("/x") void f(@RequestHeader("X-A") String a, @CookieValue("c") String c) {
        jdbc.queryForList("SELECT * FROM t WHERE a = '" + a + "' AND c = '" + c + "'");
      }`,
    ),
    expected: "confirmed",
  },
  {
    name: "@ModelAttribute fields reach the query through a getter",
    source: java(
      SPRING_IMPORTS,
      `JdbcTemplate jdbc;
      @PostMapping("/x") void f(@ModelAttribute SearchForm form) {
        jdbc.queryForList("SELECT * FROM t WHERE name = '" + form.getName() + "'");
      }`,
    ),
    expected: "confirmed",
  },
  {
    name: "an unannotated parameter of a mapped handler binds from the request",
    source: java(
      SPRING_IMPORTS,
      `JdbcTemplate jdbc;
      @GetMapping("/x") void f(String name) {
        jdbc.queryForList("SELECT * FROM t WHERE name = '" + name + "'");
      }`,
    ),
    expected: "confirmed",
  },
  {
    name: "a parameter of a plain method is an unknown value, reported low",
    source: java(
      SPRING_IMPORTS,
      `JdbcTemplate jdbc;
      void f(String name) {
        jdbc.queryForList("SELECT * FROM t WHERE name = '" + name + "'");
      }`,
    ),
    expected: "untraced",
  },
  {
    name: "a value that is not a built string and has no source is not reported",
    source: java(
      SPRING_IMPORTS,
      `JdbcTemplate jdbc;
      void f(String sql) { jdbc.queryForList(sql); }`,
    ),
    expected: "none",
  },
  {
    name: "request input passed straight in is reported",
    source: java(
      SPRING_IMPORTS,
      `JdbcTemplate jdbc;
      @GetMapping("/x") void f(@RequestParam String sql) { jdbc.queryForList(sql); }`,
    ),
    expected: "confirmed",
  },
  {
    name: "getParameter through a local variable is suspected, not confirmed",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest request) throws Exception {
        String a = request.getParameter("a");
        String sql = "SELECT * FROM t WHERE a = " + a;
        st.executeQuery(sql);
      }`,
    ),
    expected: "suspected",
  },
  {
    name: "taint survives trim(), toLowerCase() and an unknown helper",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest r) throws Exception {
        String a = escape(r.getParameter("a").trim().toLowerCase());
        st.executeQuery("SELECT * FROM t WHERE a = '" + a + "'");
      }`,
    ),
    expected: "suspected",
  },
  // ---- building the string ----
  {
    name: "String.format with %s",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest r) throws Exception {
        st.executeQuery(String.format("SELECT * FROM t WHERE a = '%s'", r.getParameter("a")));
      }`,
    ),
    expected: "confirmed",
  },
  {
    name: "String.format with only %d is inferred safe",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest r) throws Exception {
        st.executeQuery(String.format("SELECT * FROM t LIMIT %d", r.getParameter("a")));
      }`,
    ),
    expected: "inferred",
  },
  {
    name: ".formatted()",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest r) throws Exception {
        st.executeQuery("SELECT * FROM t WHERE a = '%s'".formatted(r.getParameter("a")));
      }`,
    ),
    expected: "confirmed",
  },
  {
    name: "a text block with concatenation",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest r) throws Exception {
        String sql = """
            SELECT * FROM t
            WHERE a = '""" + r.getParameter("a") + "'";
        st.executeQuery(sql);
      }`,
    ),
    expected: "suspected",
  },
  {
    name: "StringBuilder chain",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest r) throws Exception {
        StringBuilder sb = new StringBuilder("SELECT * FROM t WHERE a = '");
        sb.append(r.getParameter("a")).append("'");
        st.executeQuery(sb.toString());
      }`,
    ),
    expected: "suspected",
  },
  {
    name: "StringBuilder made only of literals is fixed text",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, boolean x) throws Exception {
        StringBuilder sb = new StringBuilder("SELECT * FROM t WHERE 1 = 1");
        if (x) sb.append(" AND a = 1");
        st.executeQuery(sb.toString());
      }`,
    ),
    expected: "none",
  },
  {
    name: "a StringBuilder handed to an unknown helper may be appended to there",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st) throws Exception {
        StringBuilder sb = new StringBuilder("SELECT * FROM t WHERE 1 = 1");
        addFilters(sb);
        st.executeQuery(sb.toString());
      }`,
    ),
    expected: "untraced",
  },
  {
    name: "String.join and concat",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest r) throws Exception {
        st.executeQuery("SELECT * FROM t WHERE a IN (" + String.join(",", r.getParameterValues("a")) + ")");
      }`,
    ),
    expected: "confirmed",
  },
  // ---- fixed text ----
  {
    name: "literals, static final constants and a constant built from them",
    source: java(
      JDBC_IMPORTS,
      `static final String TABLE = "users";
      private static final String SELECT = "SELECT * FROM " + TABLE;
      void f(Statement st) throws Exception {
        st.executeQuery(SELECT + " WHERE active = 1");
      }`,
    ),
    expected: "none",
  },
  {
    name: "a non-final field is not fixed",
    source: java(
      JDBC_IMPORTS,
      `static String table = "users";
      void f(Statement st) throws Exception {
        st.executeQuery("SELECT * FROM " + table);
      }`,
    ),
    expected: "untraced",
  },
  {
    name: "a final field assigned in a constructor is not fixed",
    source: java(
      JDBC_IMPORTS,
      `private final String table;
      A(String table) { this.table = table; }
      void f(Statement st) throws Exception {
        st.executeQuery("SELECT * FROM " + table);
      }`,
    ),
    expected: "untraced",
  },
  {
    name: "enum name() and an enum constant",
    source: java(
      JDBC_IMPORTS,
      `enum Dir { ASC, DESC }
      void f(Statement st, Dir d) throws Exception {
        st.executeQuery("SELECT * FROM t ORDER BY a " + d.name());
        st.executeQuery("SELECT * FROM t ORDER BY a " + Dir.DESC.name());
      }`,
    ),
    expected: "none",
  },
  // ---- binding identity ----
  {
    name: "a local that shadows a constant field does not inherit its constness",
    source: java(
      JDBC_IMPORTS,
      `static final String TABLE = "users";
      void f(Statement st, HttpServletRequest r) throws Exception {
        String TABLE = r.getParameter("t");
        st.executeQuery("SELECT * FROM " + TABLE);
      }`,
    ),
    expected: "suspected",
  },
  {
    name: "a parameter that shadows a constant field does not inherit its constness",
    source: java(
      JDBC_IMPORTS,
      `static final String TABLE = "users";
      void f(Statement st, String TABLE) throws Exception {
        st.executeQuery("SELECT * FROM " + TABLE);
      }`,
    ),
    expected: "untraced",
  },
  {
    name: "this.field still reaches the constant when a local has the same name",
    source: java(
      JDBC_IMPORTS,
      `static final String TABLE = "users";
      void f(Statement st, HttpServletRequest r) throws Exception {
        String TABLE = r.getParameter("t");
        st.executeQuery("SELECT * FROM " + this.TABLE);
      }`,
    ),
    expected: "none",
  },
  {
    name: "a local that shadows a mutable field is judged by its own value",
    source: java(
      JDBC_IMPORTS,
      `String table = System.getenv("T");
      void f(Statement st) throws Exception {
        String table = "fixed_table";
        st.executeQuery("SELECT * FROM " + table);
      }`,
    ),
    expected: "none",
  },
  {
    name: "a lambda parameter shadows an outer constant",
    source: java(
      JDBC_IMPORTS,
      `static final String COL = "id";
      void f(Statement st, java.util.List<String> cols) throws Exception {
        cols.forEach(COL -> st.executeQuery("SELECT " + COL + " FROM t"));
      }`,
    ),
    expected: "untraced",
  },
  {
    name: "a block-scoped local does not leak out of its block",
    source: java(
      JDBC_IMPORTS,
      `static final String TABLE = "users";
      void f(Statement st, HttpServletRequest r) throws Exception {
        { String TABLE = r.getParameter("t"); }
        st.executeQuery("SELECT * FROM " + TABLE);
      }`,
    ),
    expected: "none",
  },
  // ---- reassignment ----
  {
    name: "reassignment with +=",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest r) throws Exception {
        String q = "SELECT * FROM t";
        q += " WHERE a = '" + r.getParameter("a") + "'";
        st.executeQuery(q);
      }`,
    ),
    expected: "suspected",
  },
  {
    name: "reassignment to a literal replaces an earlier tainted value",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest r) throws Exception {
        String q = r.getParameter("a");
        q = "SELECT 1";
        st.executeQuery(q);
      }`,
    ),
    expected: "none",
  },
  {
    name: "a conditional reassignment keeps the tainted value",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest r, boolean b) throws Exception {
        String q = "SELECT 1 FROM t WHERE a = '";
        String a = "x";
        if (b) { a = r.getParameter("a"); }
        st.executeQuery(q + a + "'");
      }`,
    ),
    expected: "suspected",
  },
  {
    name: "an append inside a loop reaches a use earlier in the loop",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest r) throws Exception {
        String q = "SELECT * FROM t WHERE 1 = 1";
        for (String p : r.getParameterValues("p")) {
          st.executeQuery(q);
          q += " AND a = '" + p + "'";
        }
      }`,
    ),
    expected: "suspected",
  },
  // ---- inferred safety (low) ----
  {
    name: "Integer.parseInt of the whole value",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest r) throws Exception {
        int n = Integer.parseInt(r.getParameter("n"));
        st.executeQuery("SELECT * FROM t LIMIT " + n);
      }`,
    ),
    expected: "inferred",
  },
  {
    name: "Long.valueOf inline",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest r) throws Exception {
        st.executeQuery("SELECT * FROM t WHERE id = " + Long.valueOf(r.getParameter("id")));
      }`,
    ),
    expected: "inferred",
  },
  {
    name: "an allowlist guard that exits",
    source: java(
      JDBC_IMPORTS,
      `static final java.util.Set<String> OK = java.util.Set.of("a", "b");
      void f(Statement st, HttpServletRequest r) throws Exception {
        String col = r.getParameter("c");
        if (!OK.contains(col)) { throw new IllegalArgumentException(); }
        st.executeQuery("SELECT " + col + " FROM t");
      }`,
    ),
    expected: "inferred",
  },
  {
    name: "an allowlist guard whose branch does not exit leaves the finding strong",
    source: java(
      JDBC_IMPORTS,
      `static final java.util.Set<String> OK = java.util.Set.of("a", "b");
      void f(Statement st, HttpServletRequest r) throws Exception {
        String col = r.getParameter("c");
        if (!OK.contains(col)) { log("bad"); }
        st.executeQuery("SELECT " + col + " FROM t");
      }`,
    ),
    expected: "suspected",
  },
  {
    name: "a guard on one variable does not cover another",
    source: java(
      JDBC_IMPORTS,
      `static final java.util.Set<String> OK = java.util.Set.of("a", "b");
      void f(Statement st, String col, String dir) throws Exception {
        if (!OK.contains(col)) { return; }
        st.executeQuery("SELECT * FROM t ORDER BY " + col + " " + dir);
      }`,
    ),
    expected: "untraced",
  },
  {
    name: "an allowlist guard around the sink",
    source: java(
      JDBC_IMPORTS,
      `static final java.util.List<String> OK = java.util.List.of("a", "b");
      void f(Statement st, HttpServletRequest r) throws Exception {
        String col = r.getParameter("c");
        if (OK.contains(col)) {
          st.executeQuery("SELECT " + col + " FROM t");
        }
      }`,
    ),
    expected: "inferred",
  },
  {
    name: "a ternary allowlist",
    source: java(
      JDBC_IMPORTS,
      `static final java.util.List<String> OK = java.util.List.of("a", "b");
      void f(Statement st, HttpServletRequest r) throws Exception {
        String c = r.getParameter("c");
        String col = OK.contains(c) ? c : "a";
        st.executeQuery("SELECT " + col + " FROM t");
      }`,
    ),
    expected: "inferred",
  },
  {
    name: "a guard that gives the variable a fixed value when the check fails",
    source: java(
      JDBC_IMPORTS,
      `static final java.util.List<String> OK = java.util.List.of("a", "b");
      void f(Statement st, HttpServletRequest r) throws Exception {
        String col = r.getParameter("c");
        if (!OK.contains(col)) { col = "a"; }
        st.executeQuery("SELECT " + col + " FROM t");
      }`,
    ),
    expected: "inferred",
  },
  {
    name: "a guard is forgotten when the variable is reassigned afterwards",
    source: java(
      JDBC_IMPORTS,
      `static final java.util.List<String> OK = java.util.List.of("a", "b");
      void f(Statement st, HttpServletRequest r) throws Exception {
        String col = r.getParameter("c");
        if (!OK.contains(col)) { return; }
        col = r.getParameter("other");
        st.executeQuery("SELECT " + col + " FROM t");
      }`,
    ),
    expected: "suspected",
  },
  {
    name: "a lookup in a fixed table",
    source: java(
      JDBC_IMPORTS,
      `static final java.util.Map<String, String> M = java.util.Map.of("a", "col_a");
      void f(Statement st, HttpServletRequest r) throws Exception {
        st.executeQuery("SELECT " + M.get(r.getParameter("c")) + " FROM t");
      }`,
    ),
    expected: "inferred",
  },
  {
    name: "a numeric typed parameter",
    source: java(
      SPRING_IMPORTS,
      `JdbcTemplate jdbc;
      @GetMapping("/x") void f(@RequestParam int page) {
        jdbc.queryForList("SELECT * FROM t LIMIT " + page);
      }`,
    ),
    expected: "inferred",
  },
  {
    name: "a constant-style name from another class is only inferred fixed",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st) throws Exception {
        st.executeQuery("SELECT * FROM " + Tables.USERS);
      }`,
    ),
    expected: "inferred",
  },
  // ---- not SQL ----
  {
    name: "execute(Runnable) on an executor is not SQL",
    source: java(
      "import java.util.concurrent.*;\nimport javax.servlet.http.*;\n",
      `ExecutorService ex;
      void f(HttpServletRequest r) { ex.execute(new Task("t-" + r.getParameter("a"))); }`,
    ),
    expected: "none",
  },
  // ---- Spring Data / MyBatis annotations ----
  {
    name: "Spring Data @Query with SpEL that reads an argument",
    source: java(
      "import org.springframework.data.jpa.repository.*;\n",
      `interface R {
        @Query(value = "select * from t where a = '#{[0]}'", nativeQuery = true)
        java.util.List<Object> f(String a);
      }`,
    ),
    expected: "suspected",
  },
  {
    name: "Spring Data @Query with #{#entityName}, :name, ?1 and :#{#p} is safe",
    source: java(
      "import org.springframework.data.jpa.repository.*;\n",
      `interface R {
        @Query("select e from #{#entityName} e where e.a = :a")
        java.util.List<Object> f(String a);
        @Query(value = "select * from t where a = ?1 and b = :#{#p.b}", nativeQuery = true)
        java.util.List<Object> g(String a, P p);
      }`,
    ),
    expected: "none",
  },
  {
    name: "MyBatis @Select with ${}",
    source: java(
      "import org.apache.ibatis.annotations.*;\n",
      `interface M {
        @Select("SELECT * FROM t ORDER BY \${col}")
        java.util.List<Object> f(@Param("col") String col);
      }`,
    ),
    expected: "suspected",
  },
  {
    name: "MyBatis @Update, @Insert and @Delete with ${}, an array of strings",
    source: java(
      "import org.apache.ibatis.annotations.*;\n",
      `interface M {
        @Update({"UPDATE t SET a = 1", "WHERE id = \${id}"})
        int u(String id);
        @Insert("INSERT INTO \${table} VALUES (#{v})")
        int i(String table, String v);
        @Delete("DELETE FROM t WHERE a = \${a}")
        int d(String a);
      }`,
    ),
    expected: "suspected",
  },
  {
    name: "@Delete from another library (Micronaut) is not MyBatis",
    source: java(
      "import io.micronaut.http.annotation.*;\n",
      `interface M {
        @Delete("\${api.base}/{id}")
        void d(String id);
      }`,
    ),
    expected: "none",
  },
  {
    name: "a DAO whose jdbcTemplate comes from a base class is found by its receiver and SQL text",
    source: java(
      "",
      `void f(String name) {
        jdbcTemplate.query("SELECT * FROM t WHERE n = '" + name + "'", null);
      }`,
    ),
    expected: "untraced",
  },
  {
    name: "MyBatis annotation with #{} only is safe",
    source: java(
      "import org.apache.ibatis.annotations.*;\n",
      `interface M {
        @Select("SELECT * FROM t WHERE a = #{a} AND b LIKE CONCAT('%', #{b}, '%')")
        java.util.List<Object> f(String a, String b);
      }`,
    ),
    expected: "none",
  },
  {
    name: "MyBatis ${} of a numeric parameter is only inferred safe",
    source: java(
      "import org.apache.ibatis.annotations.*;\n",
      `interface M {
        @Select("SELECT * FROM t LIMIT \${n}")
        java.util.List<Object> f(@Param("n") int n);
      }`,
    ),
    expected: "inferred",
  },
];

const KOTLIN_CASES: Case[] = [
  {
    name: "Kotlin template with $name and ${expr}",
    path: "A.kt",
    source: kotlin(
      "import org.springframework.jdbc.core.JdbcTemplate\nimport org.springframework.web.bind.annotation.*",
      `class C(private val jdbc: JdbcTemplate) {
        @GetMapping("/x")
        fun f(@RequestParam name: String, @RequestParam other: String) {
          jdbc.queryForList("SELECT * FROM t WHERE a = '$name' AND b = '\${other.trim()}'")
        }
      }`,
    ),
    expected: "confirmed",
  },
  {
    name: "Kotlin const val, string templates of constants and companion constants",
    path: "A.kt",
    source: kotlin(
      "import org.springframework.jdbc.core.JdbcTemplate",
      `private const val TABLE = "users"
      class C(private val jdbc: JdbcTemplate) {
        companion object { const val ORDER = " ORDER BY id" }
        fun f() { jdbc.queryForList("SELECT * FROM $TABLE$ORDER") }
      }`,
    ),
    expected: "none",
  },
  {
    name: "a Kotlin val that is not const is only inferred fixed",
    path: "A.kt",
    source: kotlin(
      "import org.springframework.jdbc.core.JdbcTemplate",
      `private val TABLE = "users"
      class C(private val jdbc: JdbcTemplate) {
        fun f() { jdbc.queryForList("SELECT * FROM $TABLE") }
      }`,
    ),
    expected: "inferred",
  },
  {
    name: "Kotlin local that shadows a const val",
    path: "A.kt",
    source: kotlin(
      "import org.springframework.jdbc.core.JdbcTemplate\nimport org.springframework.web.bind.annotation.*",
      `private const val TABLE = "users"
      class C(private val jdbc: JdbcTemplate) {
        @GetMapping("/x")
        fun f(@RequestParam t: String) {
          val TABLE = t
          jdbc.queryForList("SELECT * FROM $TABLE")
        }
      }`,
    ),
    expected: "suspected",
  },
  {
    name: "Ktor call.parameters, call.receive and call.request.queryParameters",
    path: "A.kt",
    source: kotlin(
      "import java.sql.Connection",
      `fun Application.m(connection: Connection) {
        routing {
          get("/a") {
            connection.createStatement().executeQuery("SELECT * FROM t WHERE a = " + call.parameters["a"])
          }
          post("/b") {
            val body = call.receive<Body>()
            connection.createStatement().executeQuery("SELECT * FROM t WHERE b = '\${body.b}'")
          }
          get("/c") {
            val q = call.request.queryParameters["q"]
            connection.createStatement().execute("DELETE FROM t WHERE c = '$q'")
          }
        }
      }`,
    ),
    expected: "confirmed",
  },
  {
    name: "Kotlin StringBuilder, buildString and format",
    path: "A.kt",
    source: kotlin(
      "import java.sql.Connection",
      `fun f(connection: Connection, call: ApplicationCall) {
        val sb = StringBuilder("SELECT * FROM t WHERE a = '")
        sb.append(call.parameters["a"])
        connection.createStatement().executeQuery(sb.toString())
      }`,
    ),
    expected: "suspected",
  },
  {
    name: "Kotlin String.format and .format()",
    path: "A.kt",
    source: kotlin(
      "import java.sql.Connection",
      `fun f(connection: Connection, call: ApplicationCall) {
        val st = connection.createStatement()
        st.executeQuery(String.format("SELECT * FROM t WHERE a = '%s'", call.parameters["a"]))
        st.executeQuery("SELECT * FROM t WHERE b = '%s'".format(call.parameters["b"]))
      }`,
    ),
    expected: "confirmed",
  },
  {
    name: "request input reaches the parameter of a let block",
    path: "A.kt",
    source: kotlin(
      "import java.sql.Connection",
      `fun f(c: Connection, call: ApplicationCall) {
        call.parameters["id"]?.let { c.createStatement().executeQuery("SELECT * FROM t WHERE id = $it") }
      }`,
    ),
    expected: "suspected",
  },
  {
    name: "request input reaches the parameter of a Java lambda",
    source: java(
      JDBC_IMPORTS,
      `void f(Statement st, HttpServletRequest r) throws Exception {
        java.util.Arrays.asList(r.getParameterValues("id")).forEach(id -> st.executeQuery("DELETE FROM t WHERE id = " + id));
      }`,
    ),
    expected: "suspected",
  },
  {
    name: "Kotlin toInt() coercion",
    path: "A.kt",
    source: kotlin(
      "import java.sql.Connection",
      `fun f(connection: Connection, call: ApplicationCall) {
        val n = call.parameters["n"]!!.toInt()
        connection.createStatement().executeQuery("SELECT * FROM t LIMIT $n")
      }`,
    ),
    expected: "inferred",
  },
  {
    name: "Kotlin require(x in ALLOWED) guard",
    path: "A.kt",
    source: kotlin(
      "import java.sql.Connection",
      `val ALLOWED = setOf("a", "b")
      fun f(connection: Connection, call: ApplicationCall) {
        val col = call.parameters["c"]!!
        require(col in ALLOWED)
        connection.createStatement().executeQuery("SELECT $col FROM t")
      }`,
    ),
    expected: "inferred",
  },
  {
    name: "Kotlin if (!x.matches(...)) return guard",
    path: "A.kt",
    source: kotlin(
      "import java.sql.Connection",
      `fun f(connection: Connection, call: ApplicationCall) {
        val col = call.parameters["c"]!!
        if (!col.matches(Regex("[a-z_]+"))) return
        connection.createStatement().executeQuery("SELECT $col FROM t")
      }`,
    ),
    expected: "inferred",
  },
  {
    name: "Kotlin literal dollar via ${'$'} is not an interpolation",
    path: "A.kt",
    source: kotlin(
      "import java.sql.Connection",
      `fun f(connection: Connection) {
        connection.createStatement().executeQuery("SELECT '\${'$'}1' FROM t")
      }`,
    ),
    expected: "none",
  },
  {
    name: "MyBatis annotation in Kotlin with an escaped dollar",
    path: "A.kt",
    source: kotlin(
      "import org.apache.ibatis.annotations.Select\nimport org.apache.ibatis.annotations.Param",
      `interface M {
        @Select("SELECT * FROM t ORDER BY \\\${col}")
        fun f(@Param("col") col: String): List<Any>
      }`,
    ),
    expected: "suspected",
  },
  {
    name: "Kotlin when-expression that picks literals is fixed",
    path: "A.kt",
    source: kotlin(
      "import java.sql.Connection",
      `fun f(connection: Connection, call: ApplicationCall) {
        val col = when (call.parameters["s"]) { "a" -> "col_a"; "b" -> "col_b"; else -> "id" }
        connection.createStatement().executeQuery("SELECT * FROM t ORDER BY $col")
      }`,
    ),
    expected: "none",
  },
];

describe("PG-SQL-005 Java and Kotlin SQL injection", () => {
  for (const testCase of [...CASES, ...KOTLIN_CASES]) {
    it(testCase.name, async () => {
      const analysis = await run(testCase.source, testCase.path);
      expect(kindOf(analysis.findings), JSON.stringify(analysis.findings, null, 1)).toBe(
        testCase.expected,
      );
    });
  }
});

describe("finding shape", () => {
  it("a strong finding from a direct source is confirmed, high severity and high confidence", async () => {
    const analysis = await run(
      java(
        JDBC_IMPORTS,
        `void f(Statement st, HttpServletRequest r) throws Exception {
          st.executeQuery("SELECT * FROM t WHERE a = " + r.getParameter("a"));
        }`,
      ),
      "src/A.java",
    );
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]).toMatchObject({
      ruleId: "PG-SQL-005",
      path: "src/A.java",
      severity: "high",
      status: "confirmed",
      confidence: "high",
    });
    expect(analysis.findings[0]?.evidence).toContain("r.getParameter");
    expect(analysis.findings[0]?.evidence).toContain("st.executeQuery");
  });

  it("inferred findings are capped at medium severity, low confidence, and end in '; inferred'", async () => {
    const analysis = await run(
      java(
        JDBC_IMPORTS,
        `void f(Statement st, HttpServletRequest r) throws Exception {
          st.executeQuery("SELECT * FROM t LIMIT " + Integer.parseInt(r.getParameter("n")));
        }`,
      ),
    );
    expect(analysis.findings[0]).toMatchObject({
      severity: "medium",
      status: "suspected",
      confidence: "low",
    });
    expect(analysis.findings[0]?.evidence.endsWith("; inferred")).toBe(true);
  });

  it("untraced dynamic SQL is medium severity at low confidence", async () => {
    const analysis = await run(
      java(
        SPRING_IMPORTS,
        `JdbcTemplate jdbc;
        void f(String c) { jdbc.queryForList("SELECT " + c + " FROM t"); }`,
      ),
    );
    expect(analysis.findings[0]).toMatchObject({
      severity: "medium",
      status: "suspected",
      confidence: "low",
    });
    expect(analysis.findings[0]?.evidence).toContain("no input source identified");
  });

  it("the same sink on one line is reported once, with the strongest evidence", async () => {
    const analysis = await run(
      java(
        JDBC_IMPORTS,
        `void f(Statement st, HttpServletRequest r, boolean b) throws Exception {
          String q = "SELECT * FROM t WHERE a = " + (b ? "1" : r.getParameter("a"));
          for (int i = 0; i < 2; i++) { st.executeQuery(q); }
        }`,
      ),
    );
    expect(analysis.findings).toHaveLength(1);
  });

  it("keeps a flow through an if/else", async () => {
    const analysis = await run(
      java(
        JDBC_IMPORTS,
        `void f(Statement st, HttpServletRequest r, boolean b) throws Exception {
          String q;
          if (b) { q = "SELECT 1"; } else { q = "SELECT * FROM t WHERE a = " + r.getParameter("a"); }
          st.executeQuery(q);
        }`,
      ),
    );
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]?.confidence).toBe("high");
  });
});

describe("robustness", () => {
  it("a 20 000-term concatenation does not overflow the stack", async () => {
    const terms = Array.from({ length: 20_000 }, (_, i) => `"p${i} " + a`).join(" + ");
    const analysis = await run(
      java(
        JDBC_IMPORTS,
        `void f(Statement st, String a) throws Exception { st.executeQuery("x" + ${terms}); }`,
      ),
    );
    expect(analysis.findings).toHaveLength(1);
  });

  it("deeply nested code is analyzed as far as the limit and flagged incomplete", async () => {
    const open = "if (a) { ".repeat(400);
    const close = " }".repeat(400);
    const analysis = await run(
      java(JDBC_IMPORTS, `void f(Statement st, boolean a) throws Exception { ${open}${close} }`),
    );
    expect(analysis.incomplete).toBe(true);
  });

  it("a file with syntax errors is still analyzed", async () => {
    const analysis = await run(
      java(
        JDBC_IMPORTS,
        `void f(Statement st, HttpServletRequest r) throws Exception {
          int x = ;
          st.executeQuery("SELECT * FROM t WHERE a = " + r.getParameter("a"));
        }`,
      ),
    );
    expect(analysis.findings.length).toBeGreaterThan(0);
  });

  it("caps the number of findings per file", async () => {
    const members = Array.from(
      { length: 40 },
      (_, i) =>
        `void m${i}(Statement st, HttpServletRequest r) throws Exception { st.executeQuery("SELECT ${i} WHERE a = " + r.getParameter("a")); }`,
    ).join("\n");
    const analysis = await run(java(JDBC_IMPORTS, members));
    expect(analysis.findings).toHaveLength(25);
    expect(analysis.capped).toBe(true);
  });
});

/** Slow Windows runners get three times the room; elsewhere the limits stay tight. */
const SLOW = process.platform === "win32" ? 3 : 1;

/** Fastest of `runs` timings in ms: one run is noisy when other test files run in parallel. */
async function bestTimeOf(runs: number, fn: () => Promise<unknown>): Promise<number> {
  let best = Infinity;
  for (let run = 0; run < runs; run += 1) {
    const start = performance.now();
    await fn();
    best = Math.min(best, performance.now() - start);
  }
  return best;
}

describe("performance", () => {
  const method = (i: number): string => `
  @GetMapping("/m${i}")
  List<Row> m${i}(@RequestParam String a, @RequestParam int n) {
    StringBuilder sb = new StringBuilder("SELECT * FROM t${i} WHERE 1 = 1");
    if (a != null) { sb.append(" AND a = '").append(a).append("'"); }
    String q = sb.toString() + " LIMIT " + n;
    for (int k = 0; k < n; k++) { q += " "; }
    return jdbc.queryForList(q);
  }
`;
  const build = (count: number): string =>
    java(
      SPRING_IMPORTS,
      `JdbcTemplate jdbc;${Array.from({ length: count }, (_, i) => method(i)).join("")}`,
    );

  it("analyzes a file near the 1 MiB limit in linear time", async () => {
    const full = build(2800);
    const quarter = build(700);
    expect(Buffer.byteLength(full)).toBeGreaterThan(700_000);
    expect(Buffer.byteLength(full)).toBeLessThan(1024 * 1024);
    let analysis = await run(full);
    const large = await bestTimeOf(3, async () => {
      analysis = await run(full);
    });
    const small = await bestTimeOf(3, () => run(quarter));
    expect(large).toBeLessThan(6000 * SLOW);
    // Four times the input: linear is about 4x, quadratic about 16x.
    expect(large / Math.max(small, 1)).toBeLessThan(10);
    expect(analysis.findings.length).toBe(25);
    expect(analysis.capped).toBe(true);
  }, 120_000);

  it("a concatenation of 20 000 distinct names stays linear", async () => {
    const names = Array.from({ length: 20_000 }, (_, i) => `v${i}`);
    const source = java(
      JDBC_IMPORTS,
      `void f(Statement st, ${names
        .slice(0, 50)
        .map((n) => `String ${n}`)
        .join(", ")}) throws Exception { st.executeQuery("x" + ${names.join(" + ")}); }`,
    );
    const started = performance.now();
    const analysis = await run(source);
    expect(performance.now() - started).toBeLessThan(5000 * SLOW);
    expect(analysis.findings).toHaveLength(1);
  }, 60_000);

  it("deeply nested loops do not multiply the work", async () => {
    const open = "for (int i = 0; i < 3; i++) { ".repeat(40);
    const close = " }".repeat(40);
    const started = performance.now();
    await run(
      java(
        JDBC_IMPORTS,
        `void f(Statement st) throws Exception { String q = "a"; ${open} q += "b"; st.executeQuery(q); ${close} }`,
      ),
    );
    expect(performance.now() - started).toBeLessThan(3000 * SLOW);
  });
});

describe("MyBatis mapper XML", () => {
  const mapper = (body: string): string =>
    `<?xml version="1.0"?>\n<mapper namespace="a.B">\n${body}\n</mapper>\n`;

  it("reports ${} in select, insert, update and delete, never #{}", () => {
    const analysis = analyzeMybatisXml(
      mapper(`<select id="a">SELECT * FROM \${t} WHERE x = #{x}</select>
<insert id="b">INSERT INTO t VALUES (\${v})</insert>
<update id="c">UPDATE t SET a = \${a}</update>
<delete id="d">DELETE FROM t WHERE id = #{id}</delete>
<delete id="e">DELETE FROM t WHERE id = \${id}</delete>`),
      "m.xml",
    );
    expect(analysis.isMapper).toBe(true);
    expect(analysis.findings.map((f) => f.cause)).toEqual([
      "select:a:t",
      "insert:b:v",
      "update:c:a",
      "delete:e:id",
    ]);
    for (const finding of analysis.findings) {
      expect(finding).toMatchObject({
        ruleId: "PG-SQL-005",
        severity: "high",
        status: "suspected",
        confidence: "medium",
      });
    }
  });

  it("reports the line of the placeholder", () => {
    const analysis = analyzeMybatisXml(
      mapper(`<select id="a">\n  SELECT *\n  FROM t\n  ORDER BY \${c}\n</select>`),
      "m.xml",
    );
    expect(analysis.findings[0]?.line).toBe(6);
  });

  it("does not read ${} in comments and does not need a closing statement for others", () => {
    const analysis = analyzeMybatisXml(
      mapper(`<!-- <select id="x">\${a}</select> -->\n<select id="y">SELECT 1</select>`),
      "m.xml",
    );
    expect(analysis.findings).toEqual([]);
  });

  it("ignores XML that is not a mapper", () => {
    const analysis = analyzeMybatisXml(`<project><name>\${x}</name></project>`, "pom.xml");
    expect(analysis).toEqual({ isMapper: false, findings: [], capped: false });
  });

  it("lowers numeric parameterType, OGNL static fields and <sql> fragments to inferred", () => {
    const analysis = analyzeMybatisXml(
      mapper(`<select id="n" parameterType="int">SELECT * FROM t LIMIT \${limit}</select>
<select id="o">SELECT * FROM \${@a.B@TABLE}</select>
<sql id="cols">\${alias}.id</sql>`),
      "m.xml",
    );
    expect(analysis.findings).toHaveLength(3);
    for (const finding of analysis.findings) {
      expect(finding).toMatchObject({ severity: "medium", confidence: "low" });
      expect(finding.evidence.endsWith("; inferred")).toBe(true);
    }
  });

  it("an unterminated statement costs one scan, not one per tag", () => {
    const body = '<select id="a">'.repeat(60_000);
    const started = performance.now();
    const analysis = analyzeMybatisXml(mapper(body), "m.xml");
    expect(analysis.findings).toEqual([]);
    expect(performance.now() - started).toBeLessThan(2000);
  });

  it("caps findings per file", () => {
    const body = Array.from({ length: 40 }, (_, i) => `<select id="s${i}">\${v${i}}</select>`).join(
      "\n",
    );
    const analysis = analyzeMybatisXml(mapper(body), "m.xml");
    expect(analysis.findings).toHaveLength(25);
    expect(analysis.capped).toBe(true);
  });
});
