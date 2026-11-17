import { describe, expect, it } from "vitest";
import {
  elJudge,
  elLeaf,
  type ModelSource,
  THYMELEAF_ESCAPE,
  thymeleafJudge,
  thymeleafLeaf,
} from "./templates.js";

/**
 * #506: the escape stripping of `thymeleafJudge` and `elJudge` used to strip 20 calls per pass and
 * call itself on the copy, which cost O(n * calls / 20) time and memory. The shipped code strips in
 * one pass and loops. The functions below are a copy of the former implementation (test only); the
 * differential tests below run both over generated bodies and require the same verdict. Only the
 * stripping and recursion are copied: the judgement of a body with no escape call left is the
 * unchanged shipped code (`elLeaf`, `thymeleafLeaf`).
 */
type Verdict = ReturnType<typeof elLeaf>;
type ElVars = Parameters<typeof elLeaf>[1];

function closingParenOld(text: string, open: number): number {
  let depth = 0;
  let quote = "";
  for (let i = open; i < text.length; i += 1) {
    const char = text[i] as string;
    if (quote !== "") {
      if (char === "\\") i += 1;
      else if (char === quote) quote = "";
    } else if (char === '"' || char === "'") quote = char;
    else if (char === "(") depth += 1;
    else if (char === ")") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function stripCallsOld(body: string, names: RegExp): string {
  let rest = body;
  for (let hops = 0; hops < 20; hops += 1) {
    const match = new RegExp(names.source).exec(rest);
    if (match === null) break;
    const open = match.index + match[0].length - 1;
    const close = closingParenOld(rest, open);
    rest = `${rest.slice(0, match.index)}'x'${close === -1 ? "" : rest.slice(close + 1)}`;
  }
  return rest;
}

const EL_ESCAPE_OLD = /(?<!\w)fn\s*:\s*escapeXml\s*\(/;

function elJudgeOld(body: string, vars: ElVars): Verdict {
  if (EL_ESCAPE_OLD.test(body)) {
    const inner = elJudgeOld(stripCallsOld(body, EL_ESCAPE_OLD), vars);
    return inner.cls === "fixed" ? { cls: "fixed", direct: false, detail: "" } : inner;
  }
  return elLeaf(body, vars);
}

function thymeleafJudgeOld(
  expression: string,
  model: ReadonlyMap<string, ModelSource[]>,
  view: string,
): Verdict {
  const body = expression.trim();
  if (/^#\{[^${}]*\}$/.test(body) || /^'[^']*'$/.test(body) || /^\|[^|$#]*\|$/.test(body)) {
    return { cls: "fixed", direct: false, detail: "" };
  }
  if (new RegExp(THYMELEAF_ESCAPE.source).test(body)) {
    const name =
      /(?<![#\w.])([#\w.]+)\s*\(/.exec(body.slice(body.search(THYMELEAF_ESCAPE)))?.[1] ??
      "an escaping helper";
    const inner = thymeleafJudgeOld(stripCallsOld(body, THYMELEAF_ESCAPE), model, view);
    if (inner.cls === "tainted") return inner;
    return { cls: "escaped", direct: false, detail: `escaped with ${name}()` };
  }
  return thymeleafLeaf(body, model, view);
}

/** A small deterministic generator (mulberry32). */
function rng(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const MODEL: ReadonlyMap<string, ModelSource[]> = new Map([
  ["linked", [{ path: "A.java", line: 3, views: ["a"] }]],
  ["byName", [{ path: "B.java", line: 9, views: [] }]],
]);
const VIEW = "a";
const EL_VARS: ElVars = new Map([["name", "tainted"]]);

const TH_CALLS = [
  "htmlEscape(",
  "#sanitize(",
  "forHtml(",
  "#strings.escapeXml(",
  "#strings.escapeJava (",
  "escapeHtml5(",
  "#a.sanitizeAll(",
  "xhtmlEscape(",
];
const TH_ATOMS = [
  "x",
  "param.q",
  "${param.q}",
  "${linked}",
  "${byName}",
  "${x}",
  "request.getParameter('a')",
  "'lit'",
  '"d"',
  "'",
  "(",
  ")",
  "+",
  " ",
  "{",
  "}",
  "|",
  "#{",
  "#",
  "$",
  "\\",
  "\n",
];
const EL_CALLS = ["fn:escapeXml(", "fn : escapeXml (", "fn:escapeXml("];
const EL_ATOMS = [
  "x",
  "param.q",
  "param['q']",
  "cookie[c]",
  "name",
  "name.v",
  "'lit'",
  '"d"',
  "1",
  "'",
  '"',
  "(",
  ")",
  "+",
  " ",
  "\\",
  "fn:escapeXmlX(",
];

function pick<T>(random: () => number, items: readonly T[]): T {
  return items[Math.floor(random() * items.length)] as T;
}

/** Random tokens with calls mixed in; `calls` forces at least that many escape calls. */
function randomBody(
  random: () => number,
  calls: readonly string[],
  atoms: readonly string[],
  minCalls: number,
  maxTokens: number,
): string {
  const parts: string[] = [];
  const count = 1 + Math.floor(random() * maxTokens);
  let open = 0;
  const addCall = (): void => {
    parts.push(pick(random, calls));
    open += 1;
  };
  for (let i = 0; i < minCalls; i += 1) {
    addCall();
    // Usually close the call at once or after an atom; sometimes nest, sometimes leave it open.
    const shape = random();
    if (shape < 0.5) {
      parts.push(pick(random, atoms));
      parts.push(")");
      open -= 1;
    } else if (shape < 0.7) {
      // nested: leave open, the next call lands inside
    } else if (shape < 0.9) {
      parts.push(")");
      open -= 1;
    }
    if (random() < 0.7) parts.push(pick(random, ["+", " + ", " ", ""]));
  }
  for (let i = 0; i < count; i += 1) {
    const kind = random();
    if (kind < 0.25) addCall();
    else if (kind < 0.4 && open > 0) {
      parts.push(")");
      open -= 1;
    } else parts.push(pick(random, atoms));
  }
  if (random() < 0.6) while (open > 0 && random() < 0.9) (parts.push(")"), (open -= 1));
  return parts.join("");
}

function compareAll(
  bodies: Iterable<string>,
  judgeThymeleaf: boolean,
): { checked: number; mismatches: string[] } {
  const mismatches: string[] = [];
  let checked = 0;
  for (const body of bodies) {
    checked += 1;
    const next = judgeThymeleaf ? thymeleafJudge(body, MODEL, VIEW) : elJudge(body, EL_VARS);
    const old = judgeThymeleaf ? thymeleafJudgeOld(body, MODEL, VIEW) : elJudgeOld(body, EL_VARS);
    if (JSON.stringify(next) !== JSON.stringify(old) && mismatches.length < 10) {
      mismatches.push(
        `${JSON.stringify(body)}\n  old ${JSON.stringify(old)}\n  new ${JSON.stringify(next)}`,
      );
    }
  }
  return { checked, mismatches };
}

function* exhaustive(tokens: readonly string[], depth: number): Generator<string> {
  function* walk(prefix: string, left: number): Generator<string> {
    yield prefix;
    if (left > 0) for (const token of tokens) yield* walk(prefix + token, left - 1);
  }
  yield* walk("", depth);
}

describe("thymeleafJudge and elJudge keep the verdict of the former recursive code (#506), except for one malformed shape", () => {
  it("agrees on every short token sequence (Thymeleaf)", () => {
    const tokens = [
      "htmlEscape(",
      "#sanitize(",
      "forHtml(",
      "x",
      "${param.q}",
      "${linked}",
      ")",
      "(",
      "+",
      "'",
      " ",
      "|",
      "#{",
      "}",
      "$",
    ];
    const { checked, mismatches } = compareAll(exhaustive(tokens, 5), true);
    expect(checked).toBeGreaterThan(700_000);
    expect(mismatches).toEqual([]);
  });

  it("agrees on every short token sequence (EL)", () => {
    const tokens = [
      "fn:escapeXml(",
      "fn : escapeXml (",
      "x",
      "param.q",
      "name",
      ")",
      "(",
      "+",
      "'",
      '"',
      " ",
      "\\",
    ];
    const { checked, mismatches } = compareAll(exhaustive(tokens, 5), false);
    expect(checked).toBeGreaterThan(200_000);
    expect(mismatches).toEqual([]);
  });

  it.each([
    ["Thymeleaf", true, TH_CALLS, TH_ATOMS],
    ["EL", false, EL_CALLS, EL_ATOMS],
  ] as const)(
    "agrees on random bodies with up to 60 escape calls (%s)",
    (_name, thymeleaf, calls, atoms) => {
      const random = rng(thymeleaf ? 506 : 1506);
      const bodies: string[] = [];
      // Around the old recursion boundary: 0..25 calls, then 38..45 and up to 60.
      for (let i = 0; i < 12_000; i += 1) {
        const minCalls = pick(random, [0, 1, 2, 5, 19, 20, 21, 22, 39, 40, 41, 42, 60]);
        bodies.push(randomBody(random, calls, atoms, minCalls, 12));
      }
      const { mismatches } = compareAll(bodies, thymeleaf);
      expect(mismatches).toEqual([]);
    },
  );

  it.each([
    ["Thymeleaf", true, "htmlEscape(x)", "${param.q}", "${linked}"],
    ["EL", false, "fn:escapeXml(x)", "param.q", "name"],
  ] as const)(
    "agrees on exactly 19, 20, 21, 40, 41 escape calls with a tail (%s)",
    (_name, thymeleaf, call, tainted, other) => {
      const bodies: string[] = [];
      for (const count of [1, 19, 20, 21, 39, 40, 41, 61]) {
        for (const tail of [
          "",
          tainted,
          other,
          "'a'",
          ")",
          "(",
          `${call}${tainted}`,
          `${call.slice(0, -2)}`,
        ]) {
          for (const joint of ["+", " + ", "", " "]) {
            bodies.push(Array.from({ length: count }, () => call).join(joint) + joint + tail);
            bodies.push(tail + joint + Array.from({ length: count }, () => call).join(joint));
            // nested
            bodies.push(
              `${call.slice(0, -2)}(`.repeat(count) + "x" + ")".repeat(count) + joint + tail,
            );
          }
        }
      }
      const { mismatches } = compareAll(bodies, thymeleaf);
      expect(mismatches).toEqual([]);
    },
  );

  it("judges a malformed expression with more than 20 escape calls on the fully stripped body", () => {
    // The former code stripped 20 calls, then ran the `#{...}` literal test on the partly stripped
    // body. Here that body still holds the unclosed last call, which swallows the closing `}`, so
    // the old code called it a literal and reported only "escaped; inferred". The new code strips
    // all 21 calls first (the unclosed one eats the `}`), so it sees the request input. It is only
    // ever stricter than before.
    const body = `#{${"htmlEscape(${a})".repeat(20)} param.q htmlEscape(a}`;
    expect(thymeleafJudgeOld(body, MODEL, VIEW).cls).toBe("escaped");
    const next = thymeleafJudge(body, MODEL, VIEW);
    expect(next.cls).toBe("tainted");
    expect(next.direct).toBe(true);
  });
});
