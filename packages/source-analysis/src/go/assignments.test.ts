import { describe, expect, it } from "vitest";
import { analyzeGoSource } from "./analyze-go.js";
import { ASSIGNED_NAMES, PARSED_NUMBER_NAMES, readLineAssignments } from "./assignments.js";

/** The regex the line scan replaces; it is the reference for the scan's results. */
const REFERENCE =
  /(^|\n)[ \t]*(?:var[ \t]+)?([\w, ]{1,200}?)(?:[ \t]+[\w.*[\]]{1,100})?[ \t]*(:=|=|\+=)[ \t]*([^\n]+)/g;

/**
 * What the analyzer reads from a match: the identifier names and, for those, the operator and
 * value. A match whose names are only blanks has no effect, so the scan may leave it out.
 */
const effective = (matches: { names: string; op: string; value: string }[]) =>
  matches
    .map((match) => ({
      names: match.names
        .split(",")
        .map((name) => name.trim())
        .filter((name) => name !== ""),
      op: match.op,
      value: match.value,
    }))
    .filter((match) => match.names.length > 0);

const reference = (code: string) =>
  effective(
    [...code.matchAll(REFERENCE)].map((match) => ({
      names: match[2] ?? "",
      op: match[3] ?? "",
      value: match[4] ?? "",
    })),
  );
const scanned = (code: string) => effective(readLineAssignments(code));

/** Small deterministic generator so a failure reproduces. */
function random(seed: number) {
  let state = seed >>> 0;
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0;
    return state / 2 ** 32;
  };
}

const PIECES = [
  " ",
  " ",
  "\t",
  "  ",
  "a",
  "b",
  "x1",
  "_",
  ",",
  ", ",
  "var",
  "var ",
  "var\t",
  "=",
  ":=",
  "+=",
  "==",
  ":",
  "+",
  "*",
  ".",
  "[",
  "]",
  "(",
  ")",
  '"#0"',
  "1",
  "0x1f",
  "\n",
  "string",
  "[]byte",
  "err",
  "q",
  " = ",
  " := ",
  "-",
];

const GO_HEADER = 'package main\nimport (\n"database/sql"\n"net/http"\n"os/exec"\n)\n';

describe("readLineAssignments", () => {
  it("matches the reference regex on generated lines", () => {
    const next = random(368);
    for (let round = 0; round < 20_000; round += 1) {
      const length = 1 + Math.floor(next() * 14);
      let code = "";
      for (let index = 0; index < length; index += 1) {
        code += PIECES[Math.floor(next() * PIECES.length)];
      }
      expect(scanned(code), JSON.stringify(code)).toEqual(reference(code));
    }
  });

  it("matches the reference regex on long names, types and blank runs", () => {
    const cases = [
      `a${",b".repeat(120)} := x`,
      `a${" ".repeat(250)}b := x`,
      `a, ${" ".repeat(250)}b := x`,
      `var ${"x".repeat(199)} T = y`,
      `var ${"x".repeat(201)} T = y`,
      `q ${"T".repeat(100)} = y`,
      `q ${"T".repeat(101)} = y`,
      `var${" ".repeat(5)}:= y`,
      `var \t  := y`,
      `\t var  \t  = `,
      `  := y`,
      `x = `,
      `x =`,
    ];
    for (const code of cases) {
      expect(scanned(code), JSON.stringify(code)).toEqual(reference(code));
    }
  });

  it("scans a 1 MiB comment in linear time", () => {
    const code = `${GO_HEADER}/*${"x".repeat(1024 * 1024)}*/ = (\n`;
    const started = performance.now();
    analyzeGoSource(code, "a.go");
    expect(performance.now() - started).toBeLessThan(1000);
  });

  it("scans a 1 MiB line of blanks ending in an unreachable operator in linear time", () => {
    const code = `${GO_HEADER}a${" ".repeat(1024 * 1024)}(=\n`;
    const started = performance.now();
    analyzeGoSource(code, "a.go");
    expect(performance.now() - started).toBeLessThan(1000);
  });

  it("scans a 256 KiB identifier and a 256 KiB name list in linear time", () => {
    for (const body of ["a".repeat(256 * 1024), "a,".repeat(128 * 1024), "a.".repeat(128 * 1024)]) {
      const started = performance.now();
      analyzeGoSource(`${GO_HEADER}func f() {\n${body}\n}\n`, "a.go");
      expect(performance.now() - started).toBeLessThan(1000);
    }
  });
});

const OLD_ASSIGNED =
  /([A-Za-z_]\w*(?:[ \t]*,[ \t]*[A-Za-z_]\w*)*)[ \t]*(?::=|(?:[-+*/|&^%]|<<|>>|&\^)?=(?!=))/g;
const OLD_PARSED =
  /([A-Za-z_]\w*(?:[ \t]*,[ \t]*[A-Za-z_]\w*)*)[ \t]*:=[ \t]*strconv\.(?:Atoi|ParseInt|ParseUint|ParseFloat|ParseBool)\(/g;

describe("name list patterns", () => {
  const all = (pattern: RegExp, code: string) =>
    [...code.matchAll(pattern)].map((match) => [match.index, match[0], match[1]]);
  const PARTS = [
    " ",
    "\t",
    "a",
    "b1",
    "_",
    "1",
    "0x1f",
    ",",
    ", ",
    ".",
    "]",
    "=",
    ":=",
    "==",
    "+=",
    "<<=",
    "&^=",
    "\n",
    "strconv.Atoi(",
    " := strconv.ParseInt(",
    "\u00e9",
    "x",
  ];

  it("find the same matches as the patterns they replace", () => {
    const next = random(202);
    for (let round = 0; round < 20_000; round += 1) {
      const length = 1 + Math.floor(next() * 12);
      let code = "";
      for (let index = 0; index < length; index += 1) {
        code += PARTS[Math.floor(next() * PARTS.length)];
      }
      expect(all(ASSIGNED_NAMES, code), JSON.stringify(code)).toEqual(all(OLD_ASSIGNED, code));
      expect(all(PARSED_NUMBER_NAMES, code), JSON.stringify(code)).toEqual(all(OLD_PARSED, code));
    }
  });
});
