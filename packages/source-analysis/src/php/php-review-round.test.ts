import { afterAll, describe, expect, it } from "vitest";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzePhpTree } from "./analyze-php.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

async function run(source: string) {
  const outcome = await runtime.parse("php", source);
  if (outcome.status !== "parsed") throw new Error(`not parsed: ${outcome.status}`);
  try {
    return analyzePhpTree(outcome.tree.rootNode, source, "a.php");
  } finally {
    outcome.dispose();
  }
}

describe("closures that write outside their own variables stay unresolved", () => {
  const cases: Record<string, string> = {
    "use by reference": `function f($db) { $sql = "SELECT * FROM t"; $add = function ($v) use (&$sql) { $sql .= " WHERE id=" . $v; }; $add($_GET['id']); $db->query($sql); }`,
    "by-reference parameter": `function f($db) { $out = ""; $add = function ($v, &$o) { $o = "x" . $v; }; $add($_GET['id'], $out); mysqli_query($db, "SELECT " . $out); }`,
    "array appended through use": `function f() { $args = ['ls']; $add = function ($v) use (&$args) { $args[] = $v; }; $add($_POST['x']); $p = new Process($args); }`,
    "builder array through use": `function f($db) { $where = []; $add = function ($v) use (&$where) { $where[] = "id=" . $v; }; $add($_GET['i']); $db->query("SELECT * FROM t WHERE " . implode(' AND ', $where)); }`,
    "property write": `class A { public $sql; function f($db) { $add = function ($v) { $this->sql = "SELECT " . $v; }; $add($_GET['i']); $db->query($this->sql); } }`,
    "global write": `function f($db) { $add = function ($v) { global $sql; $sql = "SELECT " . $v; }; $add($_GET['i']); }`,
  };
  for (const [name, code] of Object.entries(cases)) {
    it(`does not mark the area completed: ${name}`, async () => {
      const result = await run(`<?php\n${code}\n`);
      expect(result.unsupportedForms, name).toEqual(["dynamic calls"]);
    });
  }

  it("still follows a closure that only reads and returns", async () => {
    const result = await run(
      `<?php\nfunction f($c) { $base = "SELECT * FROM t WHERE id="; $q = function ($v) use ($base) { return $base . $v; }; mysqli_query($c, $q($_GET['i'])); }\n`,
    );
    expect(result.unsupportedForms).toEqual([]);
    expect(result.findings[0]).toMatchObject({ severity: "high" });
  });
});

describe("abort guards that must not count", () => {
  const sql = (guard: string, before = "") =>
    `<?php\n${before}function f() { $x = $_GET['x']; ${guard} mysqli_query($c, "SELECT * FROM t ORDER BY " . $x); }\n`;

  it("count only a real check against a constant list", async () => {
    const ok = await run(sql(`abort_unless(in_array($x, ['a', 'b'], true), 403);`));
    expect(ok.findings[0]).toMatchObject({ confidence: "low" });
  });

  it("do not count a list that holds the checked value, an assignment in an argument, or a user-defined abort_unless", async () => {
    for (const [guard, before] of [
      [`abort_unless(in_array($x, [$x], true), 403);`, ""],
      [`abort_unless(in_array($x, ['a', $x]), 403);`, ""],
      [`abort_unless(in_array($x, ['a']), $x = $_GET['y']);`, ""],
      [`abort_unless(in_array($x = $_GET['y'], ['a']), 403);`, ""],
      [`abort_if(!in_array($x, [$x]), 403);`, ""],
      [`abort_unless(in_array($x, ['a']), 403);`, "function abort_unless($c, $s) {}\n"],
      [`abort_if(!in_array($x, ['a']), 403);`, "function abort_if($c, $s) {}\n"],
    ] as const) {
      const result = await run(sql(guard, before));
      expect(result.findings[0], guard).toMatchObject({ severity: "high", confidence: "high" });
    }
  });
});

describe("Doctrine builder review", () => {
  it("reports request input going into expr() low, and stays quiet for constants", async () => {
    const low = await run(
      `<?php\nfunction f($em) { $qb = $em->createQueryBuilder(); $qb->where($qb->expr()->eq('u.a', $_GET['a'])); }\n`,
    );
    expect(low.findings).toHaveLength(1);
    expect(low.findings[0]).toMatchObject({ confidence: "low" });
    const quiet = await run(
      `<?php\nfunction f($em) { $qb = $em->createQueryBuilder(); $qb->where($qb->expr()->eq('u.a', ':a')); }\n`,
    );
    expect(quiet.findings).toHaveLength(0);
  });

  it("keeps array-form where with bound values quiet", async () => {
    const result = await run(
      `<?php\nfunction f($repo) { $q = $repo->createQueryBuilder(); $q->where([['name', '=', $_GET['x']]]); }\n`,
    );
    expect(result.findings).toHaveLength(0);
  });

  it("marks a condition built from input on an untyped receiver as unsupported", async () => {
    const result = await run(
      `<?php\nfunction f($repo) { $repo->visibleUsers()->where("name = " . $_GET['x']); }\n`,
    );
    expect(result.findings).toHaveLength(0);
    expect(result.unsupportedForms).toEqual(["query builder conditions on an untyped receiver"]);
    const bound = await run(
      `<?php\nfunction f($repo) { $repo->visibleUsers()->where('name', $_GET['x']); }\n`,
    );
    expect(bound.unsupportedForms).toEqual([]);
  });
});

describe("bounded work: many parameters", () => {
  it("handles a function with 12000 parameters quickly", async () => {
    const params = Array.from({ length: 12_000 }, (_, i) => `$p${i}`).join(", ");
    const startedAt = performance.now();
    const result = await run(`<?php\nfunction f(${params}) { return $p0; }\n`);
    expect(performance.now() - startedAt).toBeLessThan(5_000);
    expect(result.findings).toHaveLength(0);
    const closure = await run(
      `<?php\nfunction g() { $f = function (${params}) { return $p0; }; $f(1); }\n`,
    );
    expect(closure.findings).toHaveLength(0);
  });
});
