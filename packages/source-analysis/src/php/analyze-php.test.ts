import { afterAll, describe, expect, it } from "vitest";
import type { RawSourceFinding } from "../finding-factory.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzePhpTree } from "./analyze-php.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

async function run(source: string, path = "a.php") {
  const outcome = await runtime.parse("php", source);
  if (outcome.status !== "parsed") throw new Error(`not parsed: ${outcome.status}`);
  try {
    return analyzePhpTree(outcome.tree.rootNode, source, path);
  } finally {
    outcome.dispose();
  }
}

type Kind = "none" | "confirmed" | "suspected" | "untraced" | "inferred";

/** What the rule said: strong, untraced (low) or inferred (low); the strongest finding decides. */
function kindOf(findings: RawSourceFinding[]): Kind {
  if (findings.length === 0) return "none";
  const finding = findings[0] as RawSourceFinding;
  if (finding.confidence === "low") {
    return finding.evidence.endsWith("; inferred") ? "inferred" : "untraced";
  }
  return finding.status === "confirmed" ? "confirmed" : "suspected";
}

interface Case {
  name: string;
  /** Statements placed inside a function body. */
  body: string;
  expected: Kind;
  rule?: "PG-SQL-007" | "PG-CMD-005";
  /** Parameters of the wrapping function. */
  params?: string;
  /** Text placed before the function (imports, constants). */
  before?: string;
}

const wrap = (c: Case): string =>
  `<?php\n${c.before ?? ""}\nfunction f(${c.params ?? ""}) {\n${c.body}\n}\n`;

const SQL: Case[] = [
  // ---- mysqli ----
  {
    name: "mysqli_query with a concatenated $_GET value",
    body: `mysqli_query($conn, "SELECT * FROM t WHERE a = '" . $_GET['a'] . "'");`,
    expected: "confirmed",
  },
  {
    name: "mysqli_query with an interpolated $_POST value",
    body: `mysqli_query($conn, "SELECT * FROM t WHERE a = '$_POST[a]'");`,
    expected: "confirmed",
  },
  {
    name: "mysqli_query through a variable",
    body: `$id = $_GET['id'];\n$sql = "SELECT * FROM t WHERE id = $id";\nmysqli_query($conn, $sql);`,
    expected: "suspected",
  },
  {
    name: "mysqli_query with a heredoc",
    body: `$name = $_GET['name'];\n$sql = <<<SQL\nSELECT * FROM t WHERE n = '$name'\nSQL;\nmysqli_query($conn, $sql);`,
    expected: "suspected",
  },
  {
    name: "mysqli_query with .= building",
    body: `$sql = "SELECT * FROM t WHERE 1=1";\n$sql .= " AND a = " . $_GET['a'];\nmysqli_query($conn, $sql);`,
    expected: "suspected",
  },
  {
    name: "mysqli_query with sprintf %s",
    body: `mysqli_query($conn, sprintf("SELECT * FROM t WHERE a = '%s'", $_GET['a']));`,
    expected: "confirmed",
  },
  {
    name: "$mysqli->query with an interpolated request value",
    body: `$mysqli->query("SELECT * FROM t WHERE a = {$_GET['a']}");`,
    expected: "confirmed",
  },
  {
    name: "$mysqli->real_query with concatenation",
    body: `$mysqli->real_query("DELETE FROM t WHERE id = " . $_REQUEST['id']);`,
    expected: "confirmed",
  },
  {
    name: "constant query is silent",
    body: `mysqli_query($conn, "SELECT * FROM t WHERE a = 1");`,
    expected: "none",
  },
  {
    name: "constants built from literals are silent",
    before: `const TABLE = 'users';\ndefine('COL', 'name');`,
    body: `mysqli_query($conn, "SELECT " . COL . " FROM " . TABLE);`,
    expected: "none",
  },
  {
    name: "class constants built from literals are silent",
    before: `class T { const A = 'users'; const B = self::A . '_old'; }`,
    body: `mysqli_query($conn, "SELECT * FROM " . T::B);`,
    expected: "none",
  },
  {
    name: "intval is fixed safe",
    body: `$id = intval($_GET['id']);\nmysqli_query($conn, "SELECT * FROM t WHERE id = $id");`,
    expected: "none",
  },
  {
    name: "(int) cast is fixed safe",
    body: `mysqli_query($conn, "SELECT * FROM t WHERE id = " . (int) $_GET['id']);`,
    expected: "none",
  },
  {
    name: "mysqli_real_escape_string is demoted, not silent",
    body: `$n = mysqli_real_escape_string($conn, $_GET['n']);\nmysqli_query($conn, "SELECT * FROM t WHERE n = '$n'");`,
    expected: "inferred",
  },
  {
    name: "addslashes is demoted, not silent",
    body: `mysqli_query($conn, "SELECT * FROM t WHERE n = '" . addslashes($_GET['n']) . "'");`,
    expected: "inferred",
  },
  {
    name: "PDO quote is demoted, not silent",
    body: `$n = $pdo->quote($_GET['n']);\n$pdo->query("SELECT * FROM t WHERE n = $n");`,
    expected: "inferred",
  },
  {
    name: "sprintf %d is demoted, not silent",
    body: `mysqli_query($conn, sprintf("SELECT * FROM t WHERE id = %d", $_GET['id']));`,
    expected: "inferred",
  },
  {
    name: "a value with no known source is reported at low confidence",
    params: "$table",
    body: `mysqli_query($conn, "SELECT * FROM " . $table);`,
    expected: "untraced",
  },
  {
    name: "a bare parameter says nothing about how the text was made",
    params: "$sql",
    body: `mysqli_query($conn, $sql);`,
    expected: "none",
  },
  {
    name: "result of a helper that got request input is reported low",
    body: `mysqli_query($conn, build_sql($_GET['a']));`,
    expected: "inferred",
  },
  // ---- PDO ----
  {
    name: "PDO query with concatenation",
    body: `$pdo = new PDO('sqlite::memory:');\n$pdo->query("SELECT * FROM t WHERE a = '" . $_GET['a'] . "'");`,
    expected: "confirmed",
  },
  {
    name: "PDO exec with interpolation",
    body: `$this->pdo->exec("DELETE FROM t WHERE id = {$request->input('id')}");`,
    params: "Request $request",
    expected: "confirmed",
  },
  {
    name: "PDO prepare with a concatenated string",
    body: `$stmt = $pdo->prepare("SELECT * FROM t WHERE a = '" . $_GET['a'] . "'");\n$stmt->execute();`,
    expected: "confirmed",
  },
  {
    name: "PDO prepare with an interpolated column",
    body: `$col = $_GET['col'];\n$stmt = $db->prepare("SELECT * FROM t ORDER BY $col");\n$stmt->execute();`,
    expected: "suspected",
  },
  {
    name: "PDO prepared statement with named placeholder is safe",
    body: `$stmt = $pdo->prepare('SELECT * FROM t WHERE a = :a');\n$stmt->execute(['a' => $_GET['a']]);`,
    expected: "none",
  },
  {
    name: "PDO prepared statement with positional placeholder and bindParam is safe",
    body: `$stmt = $pdo->prepare('SELECT * FROM t WHERE a = ?');\n$stmt->bindParam(1, $_GET['a']);\n$stmt->execute();`,
    expected: "none",
  },
  {
    name: "->query on an object that is not a database is ignored",
    body: `$client->query($_GET['q']);`,
    expected: "none",
  },
  {
    name: "->query with SQL text on any receiver is checked",
    body: `$x->query("SELECT * FROM t WHERE a = " . $_GET['a']);`,
    expected: "confirmed",
  },
  // ---- Laravel ----
  {
    name: "DB::raw with interpolation",
    before: `use Illuminate\\Support\\Facades\\DB;`,
    body: `$rows = DB::table('t')->select(DB::raw("count(*) as {$_GET['alias']}"))->get();`,
    expected: "confirmed",
  },
  {
    name: "DB::select with a built string and bindings",
    before: `use Illuminate\\Support\\Facades\\DB;`,
    params: "Request $request",
    body: `DB::select("SELECT * FROM users WHERE name = '" . $request->input('name') . "' AND a = ?", [1]);`,
    expected: "confirmed",
  },
  {
    name: "DB::statement with a variable-built string",
    before: `use Illuminate\\Support\\Facades\\DB;`,
    params: "Request $request",
    body: `$t = $request->get('table');\nDB::statement("DROP TABLE $t");`,
    expected: "suspected",
  },
  {
    name: "DB::unprepared with concatenation",
    params: "Request $request",
    body: `DB::unprepared('UPDATE t SET a = ' . $request->a);`,
    expected: "confirmed",
  },
  {
    name: "DB::select with placeholders is safe",
    params: "Request $request",
    body: `DB::select('SELECT * FROM users WHERE id = ?', [$request->input('id')]);`,
    expected: "none",
  },
  {
    name: "whereRaw with interpolation",
    params: "Request $request",
    body: `User::whereRaw("name = '{$request->input('name')}'")->get();`,
    expected: "confirmed",
  },
  {
    name: "whereRaw with bindings is safe",
    params: "Request $request",
    body: `User::whereRaw('name = ?', [$request->input('name')])->get();`,
    expected: "none",
  },
  {
    name: "orderByRaw with a request column",
    params: "Request $request",
    body: `$q = User::query();\n$q->orderByRaw($request->input('sort') . ' desc');`,
    expected: "confirmed",
  },
  {
    name: "selectRaw and havingRaw with built strings",
    params: "Request $request",
    body: `User::selectRaw("sum($request->col) as s")->havingRaw("s > " . $request->min)->get();`,
    expected: "confirmed",
  },
  {
    name: "orderByRaw with a constant is safe",
    body: `User::orderByRaw('created_at desc')->get();`,
    expected: "none",
  },
  {
    name: "the request is read through the request() helper",
    body: `User::whereRaw("a = " . request('a'))->get();`,
    expected: "confirmed",
  },
  {
    name: "the Request facade",
    before: `use Illuminate\\Support\\Facades\\Request;`,
    body: `User::whereRaw("a = " . Request::input('a'))->get();`,
    expected: "confirmed",
  },
  // ---- Doctrine ----
  {
    name: "Doctrine createQuery with concatenation",
    params: "Request $request",
    body: `$em->createQuery("SELECT u FROM User u WHERE u.name = '" . $request->query->get('name') . "'");`,
    expected: "confirmed",
  },
  {
    name: "Doctrine executeQuery with concatenation",
    params: "Connection $connection, Request $request",
    body: `$connection->executeQuery("SELECT * FROM t WHERE a = " . $request->get('a'));`,
    expected: "confirmed",
  },
  {
    name: "Doctrine createQuery with setParameter is safe",
    params: "Request $request",
    body: `$em->createQuery('SELECT u FROM User u WHERE u.name = :n')->setParameter('n', $request->get('n'));`,
    expected: "none",
  },
  {
    name: "Doctrine executeQuery with placeholders is safe",
    params: "Connection $connection, Request $request",
    body: `$connection->executeQuery('SELECT * FROM t WHERE a = ?', [$request->get('a')]);`,
    expected: "none",
  },
  // ---- guards ----
  {
    name: "in_array allowlist that exits on failure is demoted",
    body: `$col = $_GET['col'];\nif (!in_array($col, ['name', 'email'], true)) { return; }\nmysqli_query($conn, "SELECT * FROM t ORDER BY $col");`,
    expected: "inferred",
  },
  {
    name: "in_array allowlist inside the success branch is demoted",
    body: `$col = $_GET['col'];\nif (in_array($col, ['name', 'email'], true)) {\n  mysqli_query($conn, "SELECT * FROM t ORDER BY $col");\n}`,
    expected: "inferred",
  },
  {
    name: "a check that does not exit does not count",
    body: `$col = $_GET['col'];\nif (!in_array($col, ['name', 'email'], true)) { $x = 1; }\nmysqli_query($conn, "SELECT * FROM t ORDER BY $col");`,
    expected: "suspected",
  },
  {
    name: "a check in the failure branch does not count for the success path",
    body: `$col = $_GET['col'];\nif (in_array($col, ['name'], true)) { $ok = 1; } else {\n  mysqli_query($conn, "SELECT * FROM t ORDER BY $col");\n}`,
    expected: "suspected",
  },
  {
    name: "a guard that throws counts",
    body: `$col = $_GET['col'];\nif (!in_array($col, ['a', 'b'])) { throw new Exception('bad'); }\nmysqli_query($conn, "SELECT * FROM t ORDER BY $col");`,
    expected: "inferred",
  },
  {
    name: "a guard with die counts",
    body: `$id = $_GET['id'];\nif (!ctype_digit($id)) { die('bad'); }\nmysqli_query($conn, "SELECT * FROM t WHERE id = $id");`,
    expected: "inferred",
  },
  {
    name: "is_numeric with continue in a loop counts",
    body: `foreach ($_GET['ids'] as $id) {\n  if (!is_numeric($id)) { continue; }\n  mysqli_query($conn, "SELECT * FROM t WHERE id = $id");\n}`,
    expected: "inferred",
  },
  {
    name: "a guard on one branch only leaves the other path unguarded",
    body: `$col = $_GET['col'];\nif ($x) {\n  if (!in_array($col, ['a'], true)) { return; }\n}\nmysqli_query($conn, "SELECT * FROM t ORDER BY $col");`,
    expected: "suspected",
  },
  {
    name: "anchored preg_match that exits on failure counts",
    body: `$c = $_GET['c'];\nif (!preg_match('/^[a-z_]+$/', $c)) { return; }\nmysqli_query($conn, "SELECT * FROM t ORDER BY $c");`,
    expected: "inferred",
  },
  {
    name: "an unanchored preg_match does not count",
    body: `$c = $_GET['c'];\nif (!preg_match('/[a-z_]+/', $c)) { return; }\nmysqli_query($conn, "SELECT * FROM t ORDER BY $c");`,
    expected: "suspected",
  },
  {
    name: "equality with a literal inside the branch",
    body: `$d = $_GET['d'];\nif ($d === 'asc' || $d === 'desc') {\n  mysqli_query($conn, "SELECT * FROM t ORDER BY a $d");\n}`,
    expected: "inferred",
  },
  {
    name: "array lookup in a fixed table is demoted",
    body: `$map = ['a' => 'name', 'b' => 'email'];\n$col = $map[$_GET['c']] ?? 'name';\nmysqli_query($conn, "SELECT * FROM t ORDER BY $col");`,
    expected: "inferred",
  },
  {
    name: "ternary allowlist is demoted",
    body: `$dir = $_GET['d'] === 'desc' ? 'DESC' : 'ASC';\nmysqli_query($conn, "SELECT * FROM t ORDER BY a $dir");`,
    expected: "none",
  },
  {
    name: "property initialised with a literal and not reassigned is demoted",
    before: `class R { private $table = 'users';\n function f($conn) { mysqli_query($conn, "SELECT * FROM " . $this->table); } }`,
    body: ``,
    expected: "inferred",
  },
  {
    name: "property assigned elsewhere is untraced",
    before: `class R { private $table = 'users';\n function set($t) { $this->table = $t; }\n function f($conn) { mysqli_query($conn, "SELECT * FROM " . $this->table); } }`,
    body: ``,
    expected: "untraced",
  },
  {
    name: "constant from another file is demoted",
    body: `mysqli_query($conn, "SELECT * FROM " . Schema::TABLE);`,
    expected: "inferred",
  },
  {
    name: "closure bodies are analyzed",
    body: `$fn = function () use ($conn) {\n  mysqli_query($conn, "SELECT " . $_GET['c']);\n};`,
    expected: "confirmed",
  },
  {
    name: "arrow function bodies are analyzed",
    body: `$fn = fn ($c) => mysqli_query($c, "SELECT " . $_GET['c']);`,
    expected: "confirmed",
  },
  {
    name: "methods are analyzed",
    before: `class C { public function f(Request $request, $pdo) {\n $pdo->query("SELECT " . $request->input('c'));\n } }`,
    body: ``,
    expected: "confirmed",
  },
  {
    name: "a match expression of literals is fixed",
    body: `$dir = match ($_GET['d']) { 'a' => 'ASC', default => 'DESC' };\nmysqli_query($conn, "SELECT * FROM t ORDER BY a $dir");`,
    expected: "none",
  },
  {
    name: "a destructured request value",
    body: `[$a, $b] = [$_GET['a'], 'x'];\nmysqli_query($conn, "SELECT $a");`,
    expected: "suspected",
  },
  {
    name: "implode of request values",
    body: `$ids = implode(',', $_GET['ids']);\nmysqli_query($conn, "SELECT * FROM t WHERE id IN ($ids)");`,
    expected: "suspected",
  },
  {
    name: "array_map intval then implode is fixed safe",
    body: `$ids = implode(',', array_map('intval', $_GET['ids']));\nmysqli_query($conn, "SELECT * FROM t WHERE id IN ($ids)");`,
    expected: "none",
  },
  {
    name: "top-level script code is analyzed",
    before: `$id = $_GET['id'];\n$res = mysqli_query($conn, "SELECT * FROM t WHERE id=$id");`,
    body: ``,
    expected: "suspected",
  },
  {
    name: "a while loop condition assigns and the body queries",
    body: `while ($id = array_shift($_GET['ids'])) { mysqli_query($conn, "SELECT * FROM t WHERE id = $id"); }`,
    expected: "suspected",
  },
  {
    name: "implode of a placeholder list is safe",
    body: `$in = implode(',', array_fill(0, count($_GET['ids']), '?'));\n$stmt = $pdo->prepare("SELECT * FROM t WHERE id IN ($in)");`,
    expected: "none",
  },
];

const CMD: Case[] = [
  {
    name: "exec with a concatenated request value",
    body: `exec("ping -c 1 " . $_GET['host']);`,
    expected: "confirmed",
    rule: "PG-CMD-005",
  },
  {
    name: "system with interpolation",
    body: `system("ls $_POST[dir]");`,
    expected: "confirmed",
    rule: "PG-CMD-005",
  },
  {
    name: "shell_exec through a variable",
    body: `$h = $_GET['h'];\n$out = shell_exec("nslookup $h");`,
    expected: "suspected",
    rule: "PG-CMD-005",
  },
  {
    name: "passthru with sprintf",
    body: `passthru(sprintf("convert %s out.png", $_GET['f']));`,
    expected: "confirmed",
    rule: "PG-CMD-005",
  },
  {
    name: "popen with a request value",
    body: `$p = popen("tail -n 5 " . $_GET['f'], 'r');`,
    expected: "confirmed",
    rule: "PG-CMD-005",
  },
  {
    name: "proc_open with a string command",
    body: `proc_open("git log " . $_GET['ref'], $d, $pipes);`,
    expected: "confirmed",
    rule: "PG-CMD-005",
  },
  {
    name: "backtick operator",
    body: "$o = `ls $_GET[d]`;",
    expected: "confirmed",
    rule: "PG-CMD-005",
  },
  {
    name: "pcntl_exec with a request program",
    body: `pcntl_exec($_GET['bin'], ['-a']);`,
    expected: "confirmed",
    rule: "PG-CMD-005",
  },
  {
    name: "Process::fromShellCommandline",
    params: "Request $request",
    body: `$p = Process::fromShellCommandline("ls " . $request->input('d'));`,
    expected: "confirmed",
    rule: "PG-CMD-005",
  },
  {
    name: "new Process with a string command",
    body: `$p = new Process("ls " . $_GET['d']);`,
    expected: "confirmed",
    rule: "PG-CMD-005",
  },
  {
    name: "sh -c in an argument array",
    body: `$p = new Process(['sh', '-c', 'ls ' . $_GET['d']]);`,
    expected: "confirmed",
    rule: "PG-CMD-005",
  },
  {
    name: "proc_open with a program from data",
    body: `proc_open([$_GET['bin'], '-v'], $d, $pipes);`,
    expected: "confirmed",
    rule: "PG-CMD-005",
  },
  {
    name: "constant command is silent",
    body: `exec("ls -la /tmp");`,
    expected: "none",
    rule: "PG-CMD-005",
  },
  {
    name: "constants built from literals are silent",
    before: `const CMD = 'ls';`,
    body: `system(CMD . ' -la');`,
    expected: "none",
    rule: "PG-CMD-005",
  },
  {
    name: "escapeshellarg is demoted, not silent",
    body: `exec("ping -c 1 " . escapeshellarg($_GET['host']));`,
    expected: "inferred",
    rule: "PG-CMD-005",
  },
  {
    name: "intval argument is fixed",
    body: `exec("kill " . intval($_GET['pid']));`,
    expected: "none",
    rule: "PG-CMD-005",
  },
  {
    name: "array-form Process with a constant program is safe",
    body: `$p = new Process(['git', 'log', $_GET['ref']]);`,
    expected: "none",
    rule: "PG-CMD-005",
  },
  {
    name: "array-form proc_open with a constant program is safe",
    body: `proc_open(['ls', '-la', $_GET['d']], $d, $pipes);`,
    expected: "none",
    rule: "PG-CMD-005",
  },
  {
    name: "allowlist then exec is demoted",
    body: `$h = $_GET['h'];\nif (!preg_match('/^[a-z0-9.-]+$/', $h)) { exit; }\nexec("ping -c 1 $h");`,
    expected: "inferred",
    rule: "PG-CMD-005",
  },
  {
    name: "a bare parameter command is not guessed",
    params: "$cmd",
    body: `exec($cmd);`,
    expected: "none",
    rule: "PG-CMD-005",
  },
  {
    name: "unknown value inside a command string",
    params: "$dir",
    body: `exec("ls " . $dir);`,
    expected: "untraced",
    rule: "PG-CMD-005",
  },
  {
    name: "an array command that was changed after it was made is reported low",
    body: `$cmd = ['ls'];\n$cmd[] = $_GET['d'];\nproc_open($cmd, $d, $pipes);`,
    expected: "untraced",
    rule: "PG-CMD-005",
  },
  {
    name: "check or die guards what follows",
    body: `$h = $_GET['h'];\nctype_alnum($h) or die('bad');\nexec("ping -c 1 $h");`,
    expected: "inferred",
    rule: "PG-CMD-005",
  },
  {
    name: "exec method on an object is not the function",
    body: `$ssh->exec($_GET['c']);`,
    expected: "none",
    rule: "PG-CMD-005",
  },
];

describe("PHP SQL injection (PG-SQL-007)", () => {
  for (const testCase of SQL) {
    it(testCase.name, async () => {
      const analysis = await run(wrap(testCase));
      const findings = analysis.findings.filter((finding) => finding.ruleId === "PG-SQL-007");
      expect(kindOf(findings), JSON.stringify(analysis.findings.map((f) => f.evidence))).toBe(
        testCase.expected,
      );
    });
  }
});

describe("PHP command execution (PG-CMD-005)", () => {
  for (const testCase of CMD) {
    it(testCase.name, async () => {
      const analysis = await run(wrap(testCase));
      const findings = analysis.findings.filter((finding) => finding.ruleId === "PG-CMD-005");
      expect(kindOf(findings), JSON.stringify(analysis.findings.map((f) => f.evidence))).toBe(
        testCase.expected,
      );
    });
  }
});

describe("PHP analysis details", () => {
  it("reports the sink line, evidence and severity of a confirmed finding", async () => {
    const analysis = await run(
      `<?php\n$id = $_GET['id'];\n\nmysqli_query($c, "SELECT * FROM t WHERE id = " . $_GET['id']);\n`,
    );
    expect(analysis.findings).toHaveLength(1);
    expect(analysis.findings[0]).toMatchObject({
      ruleId: "PG-SQL-007",
      path: "a.php",
      line: 4,
      severity: "high",
      status: "confirmed",
      confidence: "high",
      evidence: "request input ($_GET['id']) -> concatenation -> mysqli_query",
    });
  });

  it("marks command execution from request input critical", async () => {
    const analysis = await run(`<?php\nsystem($_GET['c']);\n`);
    expect(analysis.findings[0]).toMatchObject({
      ruleId: "PG-CMD-005",
      severity: "critical",
      status: "confirmed",
    });
  });

  it("caps inferred findings at medium severity and low confidence", async () => {
    const analysis = await run(
      `<?php\nmysqli_query($c, "SELECT * FROM t WHERE n = '" . addslashes($_GET['n']) . "'");\n`,
    );
    expect(analysis.findings[0]).toMatchObject({
      severity: "medium",
      confidence: "low",
      status: "suspected",
    });
    expect(analysis.findings[0]?.evidence).toMatch(/; inferred$/);
  });

  it("handles a very long concatenation chain without overflowing the stack", async () => {
    const chain = Array.from({ length: 6000 }, (_, i) => `'a${i}'`).join(" . ");
    const analysis = await run(
      `<?php\nfunction f($c) { mysqli_query($c, "SELECT " . ${chain} . $_GET['x']); }\n`,
    );
    expect(analysis.findings.map((finding) => finding.ruleId)).toEqual(["PG-SQL-007"]);
  });

  it("flags dynamic calls with SQL-looking text as an unsupported form", async () => {
    const analysis = await run(
      `<?php\nfunction f($fn) { $fn("SELECT * FROM t WHERE a = " . $_GET['a']); }\n`,
    );
    expect(analysis.unsupportedForms).toEqual(["dynamic calls"]);
    expect(analysis.findings).toHaveLength(0);
  });

  it("names libraries with their own SQL APIs", async () => {
    const analysis = await run(
      `<?php\nfunction f($wpdb) { global $wpdb; $wpdb->get_results("SELECT 1"); }\n`,
    );
    expect(analysis.unsupportedLibraries).toEqual([{ label: "WordPress wpdb", kind: "sql" }]);
  });

  it("analyzes PHP embedded in HTML", async () => {
    const analysis = await run(
      `<html><body><?php mysqli_query($c, "SELECT * FROM t WHERE a = " . $_GET['a']); ?></body></html>`,
    );
    expect(analysis.findings).toHaveLength(1);
  });

  it("keeps one finding per line and cause", async () => {
    const analysis = await run(
      `<?php\nfor ($i = 0; $i < 3; $i++) { mysqli_query($c, "SELECT " . $_GET['a']); }\n`,
    );
    expect(analysis.findings).toHaveLength(1);
  });
});

const MODERN = `<?php
declare(strict_types=1);

namespace App\\Repository {
    use PDO;
    use Attribute;

    #[Attribute]
    final class Marker {}

    interface Repo { public function find(int $id): ?array; }

    enum Status: string {
        case Active = 'active';
        case Gone = 'gone';
        const DEFAULT = self::Active;
        public function label(): string { return ucfirst($this->value); }
    }

    abstract class Base implements Repo {
        public function __construct(protected readonly PDO $pdo, private string $table = 'users') {}
        abstract protected function columns(): array;
        public function find(int $id): ?array {
            $stmt = $this->pdo->prepare("SELECT * FROM {$this->table} WHERE id = :id");
            $stmt->execute(['id' => $id]);
            return $stmt->fetch() ?: null;
        }
        public function search(string $term, int ...$ids): array {
            $fn = strlen(...);
            $gen = (function () use ($term) { yield $term; yield from [1, 2]; })();
            foreach ($gen as $k => $v) { if ($k > 3): break; endif; }
            $r = $term?->foo?->bar ?? throw new \\RuntimeException('x');
            [$a, [$b, $c]] = [1, [2, 3]];
            ['x' => $x, 'y' => $y] = ['x' => 1, 'y' => 2];
            static fn(int $n): int => $n * 2;
            $o = new class($term) extends \\stdClass { public function __construct(public string $t) {} };
            switch ($term):
                case 'a': break;
                default: $z = 1;
            endswitch;
            try { $q = 1; } catch (\\A | \\B $e) { throw $e; } finally { $q = 2; }
            echo <<<'RAW'
              $not $interpolated
              RAW;
            return array_map(fn($i) => $i + 1, $ids);
        }
    }
}

namespace {
    function legacy() { global $db; static $cache = []; $cache[] = 1; unset($cache); return @$db->query('SELECT 1'); }
    ?>
    <ul><?php foreach ([1, 2] as $i): ?><li><?= $i ?></li><?php endforeach; ?></ul>
    <?php
}
`;

describe("PHP robustness", () => {
  it("analyzes modern syntax; only the promoted table property is reported (untraced)", async () => {
    const analysis = await run(MODERN);
    expect(analysis.findings.map((finding) => finding.cause)).toEqual(["$this->pdo->prepare"]);
    expect(analysis.incomplete).toBe(false);
  });

  it("does not choke on garbage", async () => {
    const analysis = await run("<?php function ( { $$$ ]]] <<<X\n");
    expect(Array.isArray(analysis.findings)).toBe(true);
  });

  it("flags SQL in methods with promoted constructor properties", async () => {
    const analysis = await run(`<?php
class Repo {
    public function __construct(private \\PDO $pdo) {}
    public function find(string $name): array {
        return $this->pdo->query("SELECT * FROM users WHERE name = '$name' AND x = " . $_GET['x'])->fetchAll();
    }
}`);
    expect(analysis.findings.map((finding) => finding.ruleId)).toEqual(["PG-SQL-007"]);
  });
});
