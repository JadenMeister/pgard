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
