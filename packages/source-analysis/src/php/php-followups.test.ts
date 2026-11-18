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

const DOCTRINE = "use Doctrine\\ORM\\QueryBuilder;\n";

describe("Doctrine QueryBuilder where (#325)", () => {
  it("reports a built condition on a builder made by createQueryBuilder", async () => {
    const a = await run(
      `<?php\nfunction f($em) { $qb = $em->createQueryBuilder(); $qb->select('u')->from('U', 'u')->where("u.name = '" . $_GET['n'] . "'"); }\n`,
    );
    expect(a.findings).toHaveLength(1);
    expect(a.findings[0]).toMatchObject({ ruleId: "PG-SQL-007", severity: "high" });
    const b = await run(
      `<?php\nfunction f($em) { $em->createQueryBuilder()->where('1=1')->andWhere("u.id = " . $_GET['i']); }\n`,
    );
    expect(b.findings).toHaveLength(1);
  });

  it("reports a builder passed as a QueryBuilder parameter when Doctrine is imported", async () => {
    const a = await run(
      `<?php\n${DOCTRINE}function f(QueryBuilder $qb) { $qb->orWhere("a = " . $_GET['a']); }\n`,
    );
    expect(a.findings).toHaveLength(1);
    const b = await run(
      `<?php\nfunction f(\\Doctrine\\DBAL\\Query\\QueryBuilder $qb) { $qb->having("a = " . $_GET['a']); }\n`,
    );
    expect(b.findings).toHaveLength(1);
  });

  it("does not treat a Laravel or unproven receiver as Doctrine, and keeps the partial note", async () => {
    const laravel = await run(
      `<?php\nfunction f($query) { $query->where("name = " . $_GET['n']); DB::table('t')->where('a', $_GET['a']); }\n`,
    );
    expect(laravel.findings).toHaveLength(0);
    const spatie = await run(
      `<?php\nuse Spatie\\QueryBuilder\\QueryBuilder;\nfunction f(QueryBuilder $qb) { $qb->where("a = " . $_GET['a']); }\n`,
    );
    expect(spatie.findings).toHaveLength(0);
    const unproven = await run(
      `<?php\nfunction f($em) { $this->qb->where("a = " . $_GET['a']); $em->createQueryBuilder(); }\n`,
    );
    expect(unproven.findings).toHaveLength(0);
    expect(unproven.unsupportedLibraries).toMatchObject([{ label: "Doctrine QueryBuilder" }]);
  });

  it("stays quiet for constants, bound parameters and the builder's own expressions", async () => {
    const a = await run(
      `<?php\nfunction f($em) { $qb = $em->createQueryBuilder(); $qb->where('u.id = :id')->setParameter('id', $_GET['i'])->andWhere($qb->expr()->eq('u.a', ':a')); }\n`,
    );
    expect(a.findings).toHaveLength(0);
  });
});

describe("abort_if and abort_unless guards (#325)", () => {
  const sql = (guard: string) =>
    `<?php\nfunction f() { $d = $_GET['d']; ${guard} mysqli_query($c, "SELECT * FROM t ORDER BY a " . $d); }\n`;

  it("count abort_unless(in_array) and abort_if(!in_array) as guards", async () => {
    const a = await run(sql(`abort_unless(in_array($d, ['asc', 'desc']), 422);`));
    expect(a.findings[0]).toMatchObject({ confidence: "low" });
    const b = await run(sql(`abort_if(!in_array($d, ['asc', 'desc']), 422);`));
    expect(b.findings[0]).toMatchObject({ confidence: "low" });
    const c = await run(sql(`abort_unless($d === 'asc' || $d === 'desc', 422);`));
    expect(c.findings[0]).toMatchObject({ confidence: "low" });
  });

  it("do not count the wrong polarity or another variable", async () => {
    for (const guard of [
      `abort_if(in_array($d, ['asc', 'desc']), 422);`,
      `abort_unless(!in_array($d, ['asc', 'desc']), 422);`,
      `abort_unless(in_array($other, ['asc', 'desc']), 422);`,
      `abort_if(!in_array($other, ['asc', 'desc']), 422);`,
      `abort_unless($d === 'asc' || $x, 422);`,
    ]) {
      const result = await run(sql(guard));
      expect(result.findings[0], guard).toMatchObject({ severity: "high", confidence: "high" });
    }
  });
});

describe("request input pushed into a command array (#325)", () => {
  it("keeps the source for $args[] and array_push", async () => {
    for (const push of [`$args[] = $_POST['x'];`, `array_push($args, $_POST['x']);`]) {
      const a = await run(
        `<?php\nfunction f() { $args = ['ls', '-l']; ${push} $p = new Process($args); }\n`,
      );
      expect(a.findings[0], push).toMatchObject({ severity: "medium", confidence: "medium" });
    }
  });

  it("keeps the source when the array shape is lost, and stays low for constants", async () => {
    const a = await run(
      `<?php\nfunction f($n) { $args = ['ls']; foreach ($n as $i) { $args[] = $_POST['x']; } $p = new Process($args); }\n`,
    );
    expect(a.findings[0]).toMatchObject({ severity: "medium", confidence: "medium" });
    const b = await run(
      `<?php\nfunction f() { $args = ['ls']; $args[] = '-l'; $p = new Process($args); }\n`,
    );
    expect(b.findings).toHaveLength(0);
    const c = await run(
      `<?php\nfunction f($v) { $args = ['ls']; $args[] = $v; $p = new Process($args); }\n`,
    );
    expect(c.findings[0]).toMatchObject({ confidence: "low" });
  });
});

describe("local closures (#325)", () => {
  it("does not mark a call of a local closure as an unsupported form", async () => {
    const a = await run(
      `<?php\nfunction f() { $fmt = fn($x) => strtoupper($x); return $fmt($_GET['a']); }\n`,
    );
    expect(a.unsupportedForms).toEqual([]);
    const b = await run(
      `<?php\nfunction f() { $fmt = function ($x) { return trim($x); }; return $fmt($_GET['a']); }\n`,
    );
    expect(b.unsupportedForms).toEqual([]);
  });

  it("still propagates request input through a closure into a sink", async () => {
    const a = await run(
      `<?php\nfunction f() { $q = fn($x) => "SELECT * FROM t WHERE a = " . $x; mysqli_query($c, $q($_GET['a'])); }\n`,
    );
    expect(a.findings[0]).toMatchObject({ ruleId: "PG-SQL-007", severity: "high" });
    const b = await run(
      `<?php\nfunction f() { $run = function ($c) { system($c); }; $run($_GET['c']); }\n`,
    );
    expect(b.findings[0]).toMatchObject({ ruleId: "PG-CMD-005", severity: "critical" });
    const c = await run(
      `<?php\nfunction f() { $q = function ($x) { return "SELECT " . $x; }; mysqli_query($c, $q($_GET['a'])); }\n`,
    );
    expect(c.findings[0]).toMatchObject({ severity: "high" });
    const d = await run(
      `<?php\nfunction f() { $f = fn($x) => $x; system(array_map($f, [$_GET['c']])[0]); }\n`,
    );
    expect(d.findings.length).toBeGreaterThan(0);
  });

  it("keeps the partial note for closures that cannot be resolved", async () => {
    const a = await run(
      `<?php\nfunction f($p) { $fmt = $p ? fn($x) => $x : fn($x) => trim($x); $fmt($_GET['a']); }\n`,
    );
    expect(a.unsupportedForms).toEqual(["dynamic calls"]);
    const b = await run(`<?php\nfunction f($fmt) { $fmt($_GET['a']); }\n`);
    expect(b.unsupportedForms).toEqual(["dynamic calls"]);
  });

  it("is bounded for recursive and repeated closure calls", async () => {
    const calls = Array.from({ length: 50 }, () => `$f($_GET['a']);`).join(" ");
    const a = await run(`<?php\nfunction g() { $f = fn($x) => $x; ${calls} }\n`);
    expect(a.unsupportedForms).toEqual(["dynamic calls"]);
    const b = await run(
      `<?php\nfunction g() { $f = function ($x) use (&$f) { return $f($x); }; $f($_GET['a']); }\n`,
    );
    expect(b.findings).toHaveLength(0);
  });
});

describe("bounded work on hostile input (#325)", () => {
  const LIMIT_MS = 8_000;
  const timed = async (source: string) => {
    const startedAt = performance.now();
    const result = await run(source);
    return { ms: performance.now() - startedAt, result };
  };

  it("handles many closure calls, chained closures and long builder chains", async () => {
    const calls = Array.from({ length: 3000 }, () => `$f($_GET['a']);`).join(" ");
    const many = await timed(`<?php\nfunction g() { $f = fn($x) => $x; ${calls} }\n`);
    expect(many.ms).toBeLessThan(LIMIT_MS);
    const count = 300;
    const defs = Array.from({ length: count }, (_, i) =>
      i === count - 1
        ? `$f${i} = function ($c) { system($c); };`
        : `$f${i} = function ($c) { $f${i + 1}($c); $f${i + 1}($c); };`,
    ).reverse();
    const chain = await timed(`<?php\nfunction g() { ${defs.join(" ")} $f0($_GET['x']); }\n`);
    expect(chain.ms).toBeLessThan(LIMIT_MS);
    const builder = await timed(
      `<?php\nfunction g($em) { $em->createQueryBuilder()${"->andWhere('a = 1')".repeat(3000)}->andWhere("b = " . $_GET['b']); }\n`,
    );
    expect(builder.ms).toBeLessThan(LIMIT_MS);
  });

  it("handles a long run of appends to a command array", async () => {
    const appends = Array.from({ length: 2000 }, () => `$a[] = $_GET['x'];`).join(" ");
    const result = await timed(
      `<?php\nfunction g() { $a = ['ls']; ${appends} proc_open($a, [], $p); }\n`,
    );
    expect(result.ms).toBeLessThan(LIMIT_MS);
    expect(result.result.findings[0]).toMatchObject({ confidence: "medium" });
  });
});
