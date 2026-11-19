import { afterAll, describe, expect, it } from "vitest";
import { itScaled } from "../../../../tests/support/timing.js";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzeJvmTree } from "./analyze-jvm.js";

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

async function run(source: string) {
  const outcome = await runtime.parse("java", source);
  if (outcome.status !== "parsed") throw new Error(`not parsed: ${outcome.status}`);
  try {
    return analyzeJvmTree(outcome.tree.rootNode, source, "A.java", "java");
  } finally {
    outcome.dispose();
  }
}

/** A loop that passes `p` down a chain of `n` variables, written in reverse so each pass moves it one step. */
function chainMethod(index: number, n: number): string {
  const vars = Array.from({ length: n }, (_, k) => `v${k}`);
  const declarations = vars.map((v) => `String ${v} = "";`).join("\n");
  const steps = vars
    .map((v, k) => `${v} = ${k === 0 ? "p" : vars[k - 1]};`)
    .reverse()
    .join("\n");
  return `void m${index}(java.sql.Statement st, String p) throws Exception {
${declarations}
for (int i = 0; i < 3; i++) {
${steps}
st.executeQuery("select " + ${vars[n - 1]});
}
}
`;
}
const file = (methods: number, n: number): string =>
  `import java.sql.*;\nclass A {\n${Array.from({ length: methods }, (_, i) => chainMethod(i, n)).join("")}}\n`;

describe("PG-SQL-005: the work done inside loops is capped per file (#286)", () => {
  it("analyzes an ordinary file to a fixed point and says so", async () => {
    const analysis = await run(file(3, 12));
    expect(analysis.incomplete).toBe(false);
    // The value reaches the last variable of the chain through every pass.
    expect(analysis.findings.filter((finding) => finding.ruleId === "PG-SQL-005")).toHaveLength(3);
  });

  itScaled(
    "past the budget a loop gets one pass and a loop that still changed makes the file incomplete",
    async () => {
      const analysis = await run(file(150, 39));
      // The cut is reported, never read as "nothing there".
      expect(analysis.incomplete).toBe(true);
      // The first methods run before the budget is spent and are still found.
      const lines = analysis.findings
        .filter((finding) => finding.ruleId === "PG-SQL-005")
        .map((finding) => finding.line);
      expect(lines.length).toBeGreaterThan(0);
      expect(Math.min(...lines)).toBeLessThan(120);
    },
    60_000,
  );

  it("a file whose loops settle at once is not cut", async () => {
    // One pass reaches the fixed point (nothing changes on the first), so the budget never marks it.
    const methods = Array.from(
      { length: 400 },
      (_, i) =>
        `void m${i}(java.sql.Statement st, String p) throws Exception {\nfor (int i = 0; i < 3; i++) {\nst.executeQuery("select " + p);\n}\n}\n`,
    ).join("");
    const analysis = await run(`import java.sql.*;\nclass A {\n${methods}}\n`);
    expect(analysis.incomplete).toBe(false);
  });
});
