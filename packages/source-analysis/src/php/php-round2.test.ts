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

describe("a closure that writes outside itself is partial even with constant arguments", () => {
  it("marks the area partial for use-by-reference and reference parameters", async () => {
    for (const code of [
      `function f($conn) { $sql = "SELECT 1"; $add = function () use (&$sql) { $sql = "SELECT * FROM t WHERE a = " . $_GET['a']; }; $add(); mysqli_query($conn, $sql); }`,
      `function f($conn) { $sql = ""; $q = function (&$s) { $s = "SELECT * FROM t WHERE a = " . $_GET['a']; }; $q($sql); mysqli_query($conn, $sql); }`,
      `function f($conn) { $sql = ""; $q = function (&$s) { $s = "SELECT " . $_GET['a']; }; $q($sql, 1); }`,
    ]) {
      const result = await run(`<?php\n${code}\n`);
      expect(result.unsupportedForms, code).toEqual(["dynamic calls"]);
    }
  });

  it("stays complete for a closure that only reads", async () => {
    const result = await run(
      `<?php\nfunction f() { $g = function ($v) { return $v . "x"; }; $g('a'); }\n`,
    );
    expect(result.unsupportedForms).toEqual([]);
  });
});
