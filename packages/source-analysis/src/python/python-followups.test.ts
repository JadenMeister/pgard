import { afterAll, describe, expect, it } from "vitest";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzePythonTree, type PythonAnalysis, type PythonOptions } from "./analyze-python.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

async function analyze(source: string, options: PythonOptions = {}): Promise<PythonAnalysis> {
  const outcome = await runtime.parse("python", source);
  if (outcome.status !== "parsed") throw new Error(outcome.status);
  try {
    return analyzePythonTree(outcome.tree.rootNode, source, "app.py", options);
  } finally {
    outcome.dispose();
  }
}
async function summarize(source: string, options: PythonOptions = {}): Promise<string[]> {
  return (await analyze(source, options)).findings.map(
    (finding) => `${finding.ruleId} ${finding.confidence}/${finding.severity}`,
  );
}

const FLASK = `from flask import Flask, request, abort
import sqlite3, os, subprocess, shlex, re
app = Flask(__name__)
`;
const view = (body: string): string =>
  `${FLASK}@app.route("/x")\ndef view():\n${[
    'col = request.args["c"]',
    'host = request.args["h"]',
    'cur = sqlite3.connect("x").cursor()',
    ...body.split("\n"),
  ]
    .map((line) => `    ${line}`)
    .join("\n")}\n`;

describe(".extra() receivers (#326)", () => {
  it("reports managers and querysets at high confidence", async () => {
    for (const receiver of [
      "Item.objects",
      "Item._default_manager",
      "Item.objects.filter(a=1)",
      "qs",
      "queryset",
      "self.qs",
      "my_qs",
    ]) {
      const source = `def view(request, qs, queryset, my_qs):\n    ${receiver}.extra(where=["a = " + request.GET["x"]])\n`;
      expect(await summarize(source), receiver).toEqual(["PG-SQL-006 high/high"]);
    }
  });

  it("reports SQL-looking arguments on any receiver", async () => {
    const source = `def view(request, thing):\n    thing.extra(select={"n": "SELECT count(*) FROM t WHERE a = " + request.GET["x"]})\n`;
    expect(await summarize(source)).toEqual(["PG-SQL-006 high/high"]);
  });

  it("drops a custom object's .extra() outside Django and keeps it low inside", async () => {
    const source = `class Ctx:\n    def extra(self, where=()):\n        return where\n\ndef view(request):\n    Ctx().extra(where=["a = " + request.GET["x"]])\n`;
    expect(await summarize(source)).toEqual([]);
    expect(await summarize(source, { django: true })).toEqual(["PG-SQL-006 low/medium"]);
    const imported = `import django\n${source}`;
    expect(await summarize(imported)).toEqual(["PG-SQL-006 low/medium"]);
  });
});

describe(".raw() manager check (N14) and manifest Django (N13)", () => {
  const raw = (receiver: string): string =>
    `def view(request, m):\n    ${receiver}.raw("x" + request.GET["c"])\n`;

  it("reports .raw() on objects and _default_manager without any Django hint", async () => {
    expect(await summarize(raw("Item.objects"))).toEqual(["PG-SQL-006 high/high"]);
    expect(await summarize(raw("Item._default_manager"))).toEqual(["PG-SQL-006 high/high"]);
  });

  it("does not report .raw() on look-alike receivers without a hint", async () => {
    expect(await summarize(raw("m.myobjects"))).toEqual([]);
    expect(await summarize(raw("m.objects_list"))).toEqual([]);
    expect(await summarize(raw("m"))).toEqual([]);
  });

  it("reports .raw() on any receiver when the manifest names Django, and when Django is imported", async () => {
    expect(await summarize(raw("m"), { django: true })).toEqual(["PG-SQL-006 high/high"]);
    expect(await summarize(`import django\n${raw("m")}`)).toEqual(["PG-SQL-006 high/high"]);
    expect(await summarize(raw("m"), { django: false })).toEqual([]);
  });

  it("reports RawSQL with the manifest hint and not without it", async () => {
    const source = `def view(request):\n    RawSQL("a = " + request.GET["x"], [])\n`;
    expect((await summarize(source, { django: true })).length).toBe(1);
    expect(await summarize(source)).toEqual([]);
  });
});

describe("**mapping SQL arguments (#326)", () => {
  it("reports request input inside a **mapping low", async () => {
    const source = view(
      'kw = {"sql": "SELECT " + col}\ncur.execute(**kw)\nfrom sqlalchemy import text\ntext(**kw)',
    );
    const result = await analyze(source);
    expect(result.findings.map((f) => `${f.confidence}/${f.severity}`)).toEqual([
      "low/medium",
      "low/medium",
    ]);
    expect(result.findings[0]?.evidence).toContain("inside the mapping");
  });

  it("marks a bare mapping partial and stays quiet for a constant one", async () => {
    const bare = await analyze(
      "import sqlite3\ndef run(**kw):\n    sqlite3.connect('x').cursor().execute(**kw)\n",
    );
    expect(bare.findings).toEqual([]);
    expect(bare.unsupportedForms).toEqual(["SQL passed inside a **mapping"]);
    const fixed = await analyze(
      'import sqlite3\ndef run():\n    kw = {"sql": "SELECT 1"}\n    sqlite3.connect("x").cursor().execute(**kw)\n',
    );
    expect(fixed.findings).toEqual([]);
    expect(fixed.unsupportedForms).toEqual([]);
    const other = await analyze("def run(thing, **kw):\n    thing.execute(**kw)\n");
    expect(other.unsupportedForms).toEqual([]);
  });

  it("keeps an ordinary argument next to a mapping on the normal path", async () => {
    const source = view('cur.execute("SELECT " + col, **{"x": 1})');
    expect(await summarize(source)).toEqual(["PG-SQL-006 high/high"]);
  });
});

describe("guards that were too conservative (#326)", () => {
  it("counts a method-chain shape test on the variable", async () => {
    const guarded = view(
      'if not host.replace(".", "").isalnum():\n    return "bad"\nsubprocess.run("ping " + host, shell=True)',
    );
    expect(await summarize(guarded)).toEqual(["PG-CMD-004 low/medium"]);
    const lower = view(
      'if not host.lower().replace("_", "").isalnum():\n    abort(400)\nsubprocess.run("ping " + host, shell=True)',
    );
    expect(await summarize(lower)).toEqual(["PG-CMD-004 low/medium"]);
  });

  it("does not count chains that remove characters that matter, strip(), or other variables", async () => {
    for (const test of [
      'host.replace(";", "").isalnum()',
      'host.replace(".", "x").isalnum()',
      'host.replace(".", "", 1).isalnum()',
      'host.replace("..", "").isalnum()',
      "host.strip().isalnum()",
      'other.replace(".", "").isalnum()',
      'host.replace(".", "").title().isalnum()',
    ]) {
      const source = view(
        `other = "a"\nif not ${test}:\n    return "bad"\nsubprocess.run("ping " + host, shell=True)`,
      );
      expect(await summarize(source), test).toEqual(["PG-CMD-004 high/critical"]);
    }
  });

  it("counts an except that re-raises, but not one that swallows", async () => {
    const reraise = view(
      'try:\n    if col not in ("a", "b"):\n        raise ValueError("x")\nexcept ValueError:\n    raise\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(reraise)).toEqual(["PG-SQL-006 low/medium"]);
    const returns = view(
      'try:\n    if col not in ("a", "b"):\n        raise ValueError("x")\nexcept ValueError:\n    return "bad"\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(returns)).toEqual(["PG-SQL-006 low/medium"]);
    const swallow = view(
      'try:\n    if col not in ("a", "b"):\n        raise ValueError("x")\nexcept ValueError:\n    print("ignored")\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(swallow)).toEqual(["PG-SQL-006 high/high"]);
    const mixed = view(
      'try:\n    if col not in ("a", "b"):\n        raise ValueError("x")\nexcept ValueError:\n    raise\nexcept KeyError:\n    pass\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(mixed)).toEqual(["PG-SQL-006 high/high"]);
  });

  it("counts a for/else allowlist loop only in its exact shape", async () => {
    const exact = view(
      'ALLOWED = ("a", "b")\nfor ok in ALLOWED:\n    if col == ok:\n        break\nelse:\n    abort(400)\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(exact)).toEqual(["PG-SQL-006 low/medium"]);
    const flipped = view(
      'for ok in ("a", "b"):\n    if ok == col:\n        break\nelse:\n    raise ValueError("x")\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(flipped)).toEqual(["PG-SQL-006 low/medium"]);
    const negatives = [
      // else does not leave
      'for ok in ("a", "b"):\n    if col == ok:\n        break\nelse:\n    print("none")',
      // no else
      'for ok in ("a", "b"):\n    if col == ok:\n        break',
      // the list is the caller\'s
      'allowed = request.args.getlist("l")\nfor ok in allowed:\n    if col == ok:\n        break\nelse:\n    abort(400)',
      // another variable is compared
      'for ok in ("a", "b"):\n    if host == ok:\n        break\nelse:\n    abort(400)',
      // the break is not the only thing the match does
      'for ok in ("a", "b"):\n    if col == ok:\n        seen = 1\n        break\nelse:\n    abort(400)',
      // an inequality
      'for ok in ("a", "b"):\n    if col != ok:\n        break\nelse:\n    abort(400)',
      // a second statement can break without a match
      'for ok in ("a", "b"):\n    if col == ok:\n        break\n    if host:\n        break\nelse:\n    abort(400)',
      // a comparison with something that is not the loop variable
      'for ok in ("a", "b"):\n    if col == "z":\n        break\nelse:\n    abort(400)',
    ];
    for (const loop of negatives) {
      const source = view(`${loop}\ncur.execute(f"SELECT {col} FROM t")`);
      expect(await summarize(source), loop).toEqual(["PG-SQL-006 high/high"]);
    }
  });
});

describe("lambda called through a variable (#326)", () => {
  it("raises request input reaching a sink inside the lambda to high", async () => {
    const source = `${FLASK}@app.route("/x")\ndef view():\n    run = lambda c: subprocess.run(c, shell=True)\n    run(request.args["x"])\n`;
    expect(await summarize(source)).toEqual(["PG-CMD-004 high/critical"]);
    const sqlSource = `${FLASK}@app.route("/x")\ndef view():\n    cur = sqlite3.connect("x").cursor()\n    q = lambda t: cur.execute("SELECT * FROM " + t)\n    q(request.args["t"])\n`;
    expect(await summarize(sqlSource)).toEqual(["PG-SQL-006 high/high"]);
    const keyword = `${FLASK}@app.route("/x")\ndef view():\n    run = lambda c, d=1: subprocess.run(c, shell=True)\n    run(c=request.args["x"])\n`;
    expect(await summarize(keyword)).toEqual(["PG-CMD-004 high/critical"]);
  });

  it("stays low for a lambda called with fixed or unknown data", async () => {
    const fixed = `${FLASK}@app.route("/x")\ndef view():\n    run = lambda c: subprocess.run(c, shell=True)\n    run("ls")\n`;
    expect(await summarize(fixed)).toEqual(["PG-CMD-004 low/medium"]);
    const unknown = `def view(c2):\n    run = lambda c: subprocess.run(c, shell=True)\n    run(c2)\n`;
    expect(await summarize(`import subprocess\n${unknown}`)).toEqual(["PG-CMD-004 low/medium"]);
  });

  it("does not follow a variable that may hold another lambda, and is bounded", async () => {
    const reassigned = `${FLASK}@app.route("/x")\ndef view(flag):\n    run = lambda c: print(c)\n    if flag:\n        run = lambda c: subprocess.run(c, shell=True)\n    run(request.args["x"])\n`;
    expect(await summarize(reassigned)).toEqual(["PG-CMD-004 low/medium"]);
    const calls = Array.from({ length: 60 }, () => 'run(request.args["x"])').join("\n    ");
    const many = `${FLASK}@app.route("/x")\ndef view():\n    run = lambda c: subprocess.run(c, shell=True)\n    ${calls}\n`;
    expect((await summarize(many)).length).toBe(1);
    const recursive = `${FLASK}@app.route("/x")\ndef view():\n    f = lambda c: f(c)\n    f(request.args["x"])\n`;
    expect(await summarize(recursive)).toEqual([]);
  });
});

describe("surviving mutants F2 and F7, more behaviours", () => {
  it("F2: a dynamic program is high in every position of the list", async () => {
    const source = view(
      'tool = request.args["t"]\nsubprocess.run((tool, "ls"))\nsubprocess.run([tool])\nsubprocess.run(["env", tool])\nsubprocess.run(["bash", "-c", tool])',
    );
    const found = await summarize(source);
    expect(found.slice(0, 2)).toEqual(["PG-CMD-004 high/critical", "PG-CMD-004 high/critical"]);
    expect(found.length).toBe(4);
    const fixed = view('subprocess.run(["ls", "-l"])\nsubprocess.run(["sh", "-c", "ls"])');
    expect(await summarize(fixed)).toEqual([]);
  });

  it("F7: only a constant table is an allowlist", async () => {
    for (const table of [
      'user_list = request.args.getlist("l")',
      "user_list = [col]",
      "user_list = list(request.args)",
      "user_list = sys.argv[1:]",
    ]) {
      const source = view(
        `import sys\n${table}\nif col not in user_list:\n    return "bad"\ncur.execute(f"SELECT {col} FROM t")`,
      );
      expect(await summarize(source), table).toEqual(["PG-SQL-006 high/high"]);
    }
    const constant = view(
      'allowed = ["a", "b"]\nif col not in allowed:\n    return "bad"\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(constant)).toEqual(["PG-SQL-006 low/medium"]);
    const inline = view(
      'if col not in {"a", "b"}:\n    return "bad"\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(inline)).toEqual(["PG-SQL-006 low/medium"]);
    const wrongWay = view(
      'if col in ["a", "b"]:\n    return "bad"\ncur.execute(f"SELECT {col} FROM t")',
    );
    expect(await summarize(wrongWay)).toEqual(["PG-SQL-006 high/high"]);
  });
});

describe("bounded work on hostile input (#326)", () => {
  const LIMIT_MS = 8_000;
  const timed = async (source: string): Promise<{ ms: number; result: PythonAnalysis }> => {
    const startedAt = performance.now();
    const result = await analyze(source);
    return { ms: performance.now() - startedAt, result };
  };

  it("handles a very long receiver chain before .extra()", async () => {
    const { ms } = await timed(
      `def f(request, x):\n    ${"x" + ".a".repeat(500)}.extra(where=[request.GET["q"]])\n`,
    );
    expect(ms).toBeLessThan(LIMIT_MS);
  });

  it("follows a long chain of lambdas that call each other only a few times each", async () => {
    const count = 300;
    const defs = Array.from({ length: count }, (_, i) =>
      i === count - 1
        ? `f${i} = lambda c: subprocess.run(c, shell=True)`
        : `f${i} = lambda c: (f${i + 1}(c), f${i + 1}(c))`,
    );
    const source = `import subprocess\ndef view(request):\n    ${defs.reverse().join("\n    ")}\n    f0(request.GET["x"])\n`;
    const { ms, result } = await timed(source);
    expect(ms).toBeLessThan(LIMIT_MS);
    expect(result.findings.length).toBeLessThanOrEqual(1);
  });

  it("handles many calls of one lambda and deeply nested lambdas", async () => {
    const calls = Array.from({ length: 3000 }, () => 'run(request.args["x"])').join("\n    ");
    const many = `${FLASK}@app.route("/x")\ndef view():\n    run = lambda c: subprocess.run(c, shell=True)\n    ${calls}\n`;
    const first = await timed(many);
    expect(first.ms).toBeLessThan(LIMIT_MS);
    expect(first.result.findings).toHaveLength(1);
    const nested = `f = ${"lambda a: ".repeat(400)}a\nf(1)\n`;
    expect((await timed(nested)).ms).toBeLessThan(LIMIT_MS);
  });
});
