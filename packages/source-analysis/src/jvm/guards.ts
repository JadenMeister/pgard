import { VALIDATOR_NAME } from "./jvm-names.js";

/**
 * Allowlist checks read from the text of a condition. Text, not syntax tree, because the Kotlin
 * grammar mis-parses forms such as `!ALLOWED.contains(c)`, and because the recognized forms are
 * the same in both languages. A guard only demotes a finding to low confidence; it never hides it.
 */

const IDENT = "[A-Za-z_][A-Za-z0-9_]*";
const CONTAINS = new RegExp(`\\.(?:contains|containsKey|containsValue)\\(\\s*(${IDENT})\\s*\\)$`);
const IN_FORM = new RegExp(`^(${IDENT})\\s+in\\s+\\S`);
const NOT_IN_FORM = new RegExp(`^(${IDENT})\\s+!in\\s+\\S`);
const EQUALS_LEFT = new RegExp(
  `^(${IDENT})\\.equals(?:IgnoreCase)?\\(\\s*"(?:[^"\\\\]|\\\\.)*"\\s*\\)$`,
);
const EQUALS_RIGHT = new RegExp(
  `^"(?:[^"\\\\]|\\\\.)*"\\.equals(?:IgnoreCase)?\\(\\s*(${IDENT})\\s*\\)$`,
);
const EQ_LEFT = new RegExp(`^(${IDENT})\\s*==\\s*"(?:[^"\\\\]|\\\\.)*"$`);
const EQ_RIGHT = new RegExp(`^"(?:[^"\\\\]|\\\\.)*"\\s*==\\s*(${IDENT})$`);
const NE_LEFT = new RegExp(`^(${IDENT})\\s*!=\\s*"(?:[^"\\\\]|\\\\.)*"$`);
const MATCHES_RECV = new RegExp(`^(${IDENT})\\.matches\\(`);
const MATCHES_ARG = new RegExp(
  `\\.(?:matches|matcher)\\(\\s*(${IDENT})\\s*\\)(?:\\.matches\\(\\))?$`,
);
const PATTERN_MATCHES = new RegExp(`Pattern\\.matches\\([^,]+,\\s*(${IDENT})\\s*\\)$`);
const VALIDATOR_CALL = new RegExp(`(?:^|[.\\s])(${IDENT})\\(\\s*(${IDENT})\\s*\\)$`);

/** Removes redundant outer parentheses. */
function unwrap(text: string): string {
  let value = text.trim();
  while (value.startsWith("(") && value.endsWith(")") && closesAtEnd(value)) {
    value = value.slice(1, -1).trim();
  }
  return value;
}

/** True when the opening parenthesis at 0 is closed by the last character. */
function closesAtEnd(text: string): boolean {
  let depth = 0;
  let quote: string | null = null;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i] as string;
    if (quote !== null) {
      if (char === "\\") i += 1;
      else if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") quote = char;
    else if (char === "(") depth += 1;
    else if (char === ")") {
      depth -= 1;
      if (depth === 0) return i === text.length - 1;
    }
  }
  return false;
}

/** Splits at an operator that is outside parentheses, brackets, braces and quotes. */
export function splitTop(text: string, operator: "&&" | "||"): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let last = 0;
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i] as string;
    if (quote !== null) {
      if (char === "\\") i += 1;
      else if (char === quote) quote = null;
      continue;
    }
    if (char === '"' || char === "'") quote = char;
    else if (char === "(" || char === "[" || char === "{") depth += 1;
    else if (char === ")" || char === "]" || char === "}") depth -= 1;
    else if (depth === 0 && text.startsWith(operator, i)) {
      parts.push(text.slice(last, i));
      last = i + operator.length;
      i += operator.length - 1;
    }
  }
  parts.push(text.slice(last));
  return parts.map((part) => part.trim()).filter((part) => part !== "");
}

/** Names `x` for which `term` being true means x passed an allowlist or validation check. */
function allowed(term: string): string[] {
  const value = unwrap(term);
  if (value.startsWith("!")) return [];
  let match: RegExpExecArray | null;
  if ((match = CONTAINS.exec(value))) return [match[1] as string];
  if ((match = IN_FORM.exec(value))) return [match[1] as string];
  for (const pattern of [EQUALS_LEFT, EQUALS_RIGHT, EQ_LEFT, EQ_RIGHT]) {
    if ((match = pattern.exec(value))) return [match[1] as string];
  }
  if ((match = MATCHES_RECV.exec(value))) return [match[1] as string];
  if ((match = MATCHES_ARG.exec(value))) return [match[1] as string];
  if ((match = PATTERN_MATCHES.exec(value))) return [match[1] as string];
  if ((match = VALIDATOR_CALL.exec(value)) && VALIDATOR_NAME.test(match[1] as string)) {
    return [match[2] as string];
  }
  return [];
}

// ------------------------------------------------------------------ path guards

/** A name that a path check covers. `needsCanon`: only counts when the value was canonicalized. */
export interface PathGuard {
  name: string;
  needsCanon: boolean;
}

const CANON_CALL =
  /\.(?:normalize|toRealPath|getCanonicalPath|getCanonicalFile|canonicalPath|canonicalFile)\b/;
const DOT_DOT_CONTAINS = new RegExp(
  `^(${IDENT})\\.contains\\(\\s*"(?:\\.\\./?|\\.\\.\\\\\\\\|/|\\\\\\\\)"\\s*\\)$`,
);
const NOT_DOT_DOT_CONTAINS = new RegExp(`^!\\s*${DOT_DOT_CONTAINS.source.slice(1)}`);
const PLAIN_CHAIN = /^[A-Za-z_]\w*(?:\.\w+(?:\(\))?)*$/;
const NOT_NAMES = new Set(["new", "this", "super", "true", "false", "null", "it"]);

/** Identifiers in `text` that are variables: not members (after a dot), not calls, not types. */
function variableNames(text: string): string[] {
  const bare = text.replace(/"(?:[^"\\]|\\.)*"/g, '""');
  const out: string[] = [];
  for (const match of bare.matchAll(/(?<![.\w])([A-Za-z_]\w*)(?!\w)(?!\s*\()/g)) {
    const name = match[1] as string;
    if (NOT_NAMES.has(name) || /^[A-Z]/.test(name)) continue;
    if (!out.includes(name)) out.push(name);
  }
  return out;
}

/** `<path>.startsWith(<base>)` is a guard when `<path>` was resolved (`normalize()`, real path). */
function startsWithGuard(value: string): PathGuard[] {
  const at = value.lastIndexOf(".startsWith(");
  if (at <= 0) return [];
  const call = value.slice(at + ".startsWith".length);
  if (!call.startsWith("(") || !closesAtEnd(call)) return [];
  const receiver = value.slice(0, at).trim();
  if (CANON_CALL.test(receiver)) {
    return variableNames(receiver).map((name) => ({ name, needsCanon: false }));
  }
  // `p.startsWith(base)` on a value that was resolved when it was made: checked against its value.
  if (PLAIN_CHAIN.test(receiver)) {
    const root = /^[A-Za-z_]\w*/.exec(receiver)?.[0] as string;
    return [{ name: root, needsCanon: true }];
  }
  return [];
}

/** Names x for which `term` being true means x passed a path check. */
function pathAllowed(term: string): PathGuard[] {
  const value = unwrap(term);
  let match: RegExpExecArray | null;
  if ((match = NOT_DOT_DOT_CONTAINS.exec(value))) {
    return [{ name: match[1] as string, needsCanon: false }];
  }
  if (value.startsWith("!")) return [];
  return startsWithGuard(value);
}

/** Names for which `term` being false means the same. */
function pathRejected(term: string): PathGuard[] {
  const value = unwrap(term);
  if (value.startsWith("!") && !value.startsWith("!="))
    return startsWithGuard(unwrap(value.slice(1)));
  const match = DOT_DOT_CONTAINS.exec(value);
  return match === null ? [] : [{ name: match[1] as string, needsCanon: false }];
}

const intersectGuards = (lists: PathGuard[][]): PathGuard[] => {
  const [first, ...rest] = lists;
  if (first === undefined) return [];
  return first
    .filter((guard) => rest.every((list) => list.some((other) => other.name === guard.name)))
    .map((guard) => ({
      name: guard.name,
      needsCanon:
        guard.needsCanon ||
        rest.some((list) => list.find((o) => o.name === guard.name)?.needsCanon),
    }));
};

/** Path checks that passed whenever `condition` is true. */
export function pathGuardedWhenTrue(condition: string): PathGuard[] {
  const value = unwrap(condition);
  const either = splitTop(value, "||");
  if (either.length > 1) return intersectGuards(either.map(pathGuardedWhenTrue));
  const all = splitTop(value, "&&");
  if (all.length > 1) return all.flatMap(pathGuardedWhenTrue);
  return pathAllowed(value);
}

/** Path checks that passed whenever `condition` is false. */
export function pathGuardedWhenFalse(condition: string): PathGuard[] {
  const value = unwrap(condition);
  const all = splitTop(value, "&&");
  if (all.length > 1) return intersectGuards(all.map(pathGuardedWhenFalse));
  const either = splitTop(value, "||");
  if (either.length > 1) return either.flatMap(pathGuardedWhenFalse);
  return pathRejected(value);
}

/** Names for which `term` being false means the same. */
function rejected(term: string): string[] {
  const value = unwrap(term);
  if (value.startsWith("!") && !value.startsWith("!=")) return allowed(value.slice(1));
  let match: RegExpExecArray | null;
  if ((match = NOT_IN_FORM.exec(value))) return [match[1] as string];
  if ((match = NE_LEFT.exec(value))) return [match[1] as string];
  return [];
}

const intersect = (lists: string[][]): string[] => {
  const [first, ...rest] = lists;
  return first === undefined ? [] : first.filter((name) => rest.every((l) => l.includes(name)));
};

/** Names that passed an allowlist check whenever `condition` is true. */
export function guardedWhenTrue(condition: string): string[] {
  const value = unwrap(condition);
  const either = splitTop(value, "||");
  if (either.length > 1) return intersect(either.map(guardedWhenTrue));
  const all = splitTop(value, "&&");
  if (all.length > 1) return [...new Set(all.flatMap(guardedWhenTrue))];
  return allowed(value);
}

/** Names that passed an allowlist check whenever `condition` is false. */
export function guardedWhenFalse(condition: string): string[] {
  const value = unwrap(condition);
  const all = splitTop(value, "&&");
  if (all.length > 1) return intersect(all.map(guardedWhenFalse));
  const either = splitTop(value, "||");
  if (either.length > 1) return [...new Set(either.flatMap(guardedWhenFalse))];
  return rejected(value);
}
