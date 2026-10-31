import { afterAll, describe, expect, it } from "vitest";
import { TreeSitterRuntime } from "../tree-sitter/runtime.js";
import { analyzeJvmTree, importAliasesOf, importsOf } from "./analyze-jvm.js";
import { TIME_FACTOR } from "../../../../tests/support/timing.js";

const OLD_IMPORT = /^\s*import\s+(?:static\s+)?([\w.]+(?:\.\*)?)/gm;
const OLD_ALIAS = /^\s*import\s+([\w.]+)\s+as\s+(\w+)/gm;

function random(seed: number) {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 2 ** 32;
  };
}

const runtime = new TreeSitterRuntime();
afterAll(() => runtime.dispose());

describe("JVM import patterns", () => {
  it("read the same imports and aliases as the patterns they replace", () => {
    const parts = [
      "\n",
      "\r\n",
      " ",
      "\t",
      " ",
      "﻿",
      "import",
      "import ",
      "static ",
      "a.b",
      ".*",
      " as ",
      "X",
      ";",
      "x",
      " ",
    ];
    const next = random(54);
    for (let round = 0; round < 20_000; round += 1) {
      let source = "";
      const length = 1 + Math.floor(next() * 12);
      for (let index = 0; index < length; index += 1) {
        source += parts[Math.floor(next() * parts.length)];
      }
      const oldImports = [...source.matchAll(OLD_IMPORT)].map((match) => match[1]);
      expect(importsOf(source), JSON.stringify(source)).toEqual(oldImports);
      const oldAliases = new Map<string, string>();
      for (const match of source.matchAll(OLD_ALIAS)) {
        const real = (match[1] as string).slice((match[1] as string).lastIndexOf(".") + 1);
        oldAliases.set(match[2] as string, real);
      }
      expect(importAliasesOf(source), JSON.stringify(source)).toEqual(oldAliases);
    }
  });

  it("read 1 MiB of newlines in linear time", () => {
    const source = `${"\n".repeat(1024 * 1024)}x`;
    const started = performance.now();
    importsOf(source);
    importAliasesOf(source);
    expect(performance.now() - started).toBeLessThan(1000 * TIME_FACTOR);
  });

  it.each([
    ["A.java", "java"],
    ["A.kt", "kotlin"],
  ] as const)("analyze %s with 1 MiB of newlines in linear time", async (path, language) => {
    const source = `import java.sql.*;${"\n".repeat(1024 * 1024 - 64)}class A {}\n`;
    const outcome = await runtime.parse(language, source);
    if (outcome.status !== "parsed") throw new Error(`not parsed: ${outcome.status}`);
    try {
      const started = performance.now();
      analyzeJvmTree(outcome.tree.rootNode, source, path, language);
      expect(performance.now() - started).toBeLessThan(1000 * TIME_FACTOR);
    } finally {
      outcome.dispose();
    }
  });
});
