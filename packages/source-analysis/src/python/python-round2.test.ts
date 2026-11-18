import { afterAll, describe, expect, it } from "vitest";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzePythonTree, type PythonOptions } from "./analyze-python.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

async function summarize(source: string, options: PythonOptions = {}): Promise<string[]> {
  const outcome = await runtime.parse("python", source);
  if (outcome.status !== "parsed") throw new Error(outcome.status);
  try {
    return analyzePythonTree(outcome.tree.rootNode, source, "app.py", options).findings.map(
      (f) => `${f.ruleId} ${f.confidence}/${f.severity}`,
    );
  } finally {
    outcome.dispose();
  }
}

const USE = `def view(request):\n    Ctx().extra(where=["a = " + request.GET["x"]])\n`;

describe(".extra() demotion needs a class that cannot hand out a queryset", () => {
  it("demotes a class whose own body defines extra", async () => {
    const own = `class Ctx:\n    def extra(self, where=()):\n        return where\n\n${USE}`;
    expect(await summarize(own)).toEqual([]);
    expect(await summarize(own, { django: true })).toEqual(["PG-SQL-006 low/medium"]);
  });

  it("keeps high for every way the object can be a queryset", async () => {
    const cases: Record<string, string> = {
      getattr: `class Ctx:\n    def __getattr__(self, n):\n        return getattr(User.objects, n)\n    def extra(self, where=()):\n        return where\n\n${USE}`,
      getattribute: `class Ctx:\n    def __getattribute__(self, n):\n        return getattr(User.objects, n)\n    def extra(self, where=()):\n        return where\n\n${USE}`,
      "class attribute": `class Ctx:\n    extra = User.objects.extra\n\n${USE}`,
      "no extra defined": `class Ctx:\n    pass\n\n${USE}`,
      __new__: `class Ctx:\n    def __new__(cls):\n        return User.objects.all()\n    def extra(self, where=()):\n        return where\n\n${USE}`,
      rebinding: `class Ctx:\n    def extra(self, where=()):\n        return where\n\nCtx = User.objects.all\n\n${USE}`,
      "defined twice": `class Ctx:\n    def extra(self, where=()):\n        return where\n\nclass Ctx:\n    pass\n\n${USE}`,
    };
    for (const [name, source] of Object.entries(cases)) {
      expect(await summarize(source), name).toEqual(["PG-SQL-006 high/high"]);
      expect(await summarize(source, { django: true }), `${name} (django)`).toEqual([
        "PG-SQL-006 high/high",
      ]);
    }
  });
});
