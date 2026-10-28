/**
 * Where a name list (`a`, `a, b`) may start: a letter or `_` that begins its word (only digits may
 * precede it in the word, as in `0x1f`) and that is not a later item of a list starting earlier.
 * A match that started there would be a suffix of the earlier one, so skipping those positions
 * keeps every result while a long word or list is scanned once instead of once per character.
 */
const NAME_LIST_START = String.raw`(?=[A-Za-z_])(?<![A-Za-z_]\d*)(?<![A-Za-z_]\w*?[ \t]*,[ \t]*)`;
const NAME_LIST = String.raw`([A-Za-z_]\w*(?:[ \t]*,[ \t]*[A-Za-z_]\w*)*)`;
/** `a, b := ...`, `a = ...`, `a += ...`: the names written. */
export const ASSIGNED_NAMES = new RegExp(
  String.raw`${NAME_LIST_START}${NAME_LIST}[ \t]*(?::=|(?:[-+*/|&^%]|<<|>>|&\^)?=(?!=))`,
  "g",
);
/** `n, err := strconv.Atoi(...)`. */
export const PARSED_NUMBER_NAMES = new RegExp(
  String.raw`${NAME_LIST_START}${NAME_LIST}[ \t]*:=[ \t]*strconv\.(?:Atoi|ParseInt|ParseUint|ParseFloat|ParseBool)\(`,
  "g",
);

/** One `names [type] op value` line: the raw captures, before the names are split and trimmed. */
export interface LineAssignment {
  names: string;
  op: ":=" | "=" | "+=";
  value: string;
}

const SPACE = 32;
const TAB = 9;

const isBlank = (code: number) => code === SPACE || code === TAB;
const isWord = (code: number) =>
  (code >= 48 && code <= 57) ||
  (code >= 65 && code <= 90) ||
  (code >= 97 && code <= 122) ||
  code === 95;
/** `[\w, ]`: a character of the name part. */
const isNameChar = (code: number) => isWord(code) || code === 44 || code === SPACE;
/** `[\w.*[\]]`: a character of the type part. */
const isTypeChar = (code: number) =>
  isWord(code) || code === 46 || code === 42 || code === 91 || code === 93;

/**
 * Per line, the first match of
 * `^[ \t]*(?:var[ \t]+)?([\w, ]{1,200}?)(?:[ \t]+[\w.*[\]]{1,100})?[ \t]*(:=|=|\+=)[ \t]*([^\n]+)`
 * with the regex engine's backtracking order, computed in time linear in the line length. The
 * regex itself backtracks over every split of a long run of blanks (a masked comment is one), so
 * a crafted line took minutes. A match whose names are only blanks is reported as such: callers
 * drop those names, and it ends the search for that line exactly as the regex did.
 */
export function readLineAssignments(code: string): LineAssignment[] {
  const out: LineAssignment[] = [];
  let start = 0;
  // The next "=" at or after `start` (searched forward once, so the whole scan stays linear).
  let nextEquals = -1;
  while (start <= code.length) {
    let end = code.indexOf("\n", start);
    if (end === -1) end = code.length;
    if (nextEquals !== -2 && nextEquals < start) {
      nextEquals = code.indexOf("=", start);
      if (nextEquals === -1) nextEquals = -2;
    }
    // The operator always contains "=", so a line without one cannot match.
    if (nextEquals >= start && nextEquals < end) {
      const found = matchLine(code.slice(start, end));
      if (found !== null) out.push(found);
    }
    start = end + 1;
  }
  return out;
}

function matchLine(line: string): LineAssignment | null {
  const n = line.length;
  // blankEnd[i]: first index >= i that is not a blank; typeEnd[i]: same for type characters;
  // nameEnd[i]: same for name characters.
  const blankEnd = new Int32Array(n + 1);
  const typeEnd = new Int32Array(n + 1);
  const nameEnd = new Int32Array(n + 1);
  blankEnd[n] = n;
  typeEnd[n] = n;
  nameEnd[n] = n;
  for (let index = n - 1; index >= 0; index -= 1) {
    const code = line.charCodeAt(index);
    blankEnd[index] = isBlank(code) ? (blankEnd[index + 1] as number) : index;
    typeEnd[index] = isTypeChar(code) ? (typeEnd[index + 1] as number) : index;
    nameEnd[index] = isNameChar(code) ? (nameEnd[index + 1] as number) : index;
  }
  const blank = (index: number) => blankEnd[index] as number;

  /** `[ \t]*(:=|=|\+=)[ \t]*([^\n]+)` at `at`. */
  const operatorTail = (at: number): { op: LineAssignment["op"]; value: string } | null => {
    const position = blank(at);
    let op: LineAssignment["op"];
    if (line[position] === ":" && line[position + 1] === "=") op = ":=";
    else if (line[position] === "=") op = "=";
    else if (line[position] === "+" && line[position + 1] === "=") op = "+=";
    else return null;
    const after = position + op.length;
    const valueStart = blank(after);
    if (valueStart < n) return { op, value: line.slice(valueStart) };
    // Only blanks follow: the greedy `[ \t]*` gives one back so the value has its one character.
    if (after < n) return { op, value: line.slice(n - 1) };
    return null;
  };
  /** `(?:[ \t]+[\w.*[\]]{1,100})?` then the operator tail, at `at`. */
  const tail = (at: number) => {
    const typeStart = blank(at);
    if (typeStart > at) {
      const typeLength = (typeEnd[typeStart] as number) - typeStart;
      if (typeLength >= 1 && typeLength <= 100) {
        const found = operatorTail(typeStart + typeLength);
        if (found !== null) return found;
      }
    }
    return operatorTail(at);
  };
  /** The lazy `([\w, ]{1,200}?)` from `from`, then the tail. */
  const names = (from: number): LineAssignment | null => {
    const last = Math.min(from + 200, nameEnd[from] as number);
    for (let end = from + 1; end <= last; end += 1) {
      const found = tail(end);
      if (found !== null) return { names: line.slice(from, end), ...found };
    }
    return null;
  };

  const indent = blank(0);
  if (line.startsWith("var", indent) && indent + 3 < n && isBlank(line.charCodeAt(indent + 3))) {
    // `var` followed by its blanks (greedy), then the names.
    const afterVar = blank(indent + 3);
    const found = names(afterVar);
    if (found !== null) return found;
    // The regex then gives back blanks after `var` one at a time. Names starting on a blank only
    // reach `afterVar` or stay inside the blanks (longer ones already failed above), so they match
    // only as blank names, which still end the search for this line.
    const blanks = afterVar - (indent + 3);
    const atAfterVar = tail(afterVar);
    if (blanks >= 2 && line.charCodeAt(afterVar - 1) === SPACE && atAfterVar !== null) {
      return { names: " ", ...atAfterVar };
    }
    if (blanks >= 3) {
      const inside = tail(afterVar - 1);
      for (let index = afterVar - 2; index >= indent + 4; index -= 1) {
        if (line.charCodeAt(index) === SPACE && inside !== null) {
          return { names: line.slice(index, index + 1), ...inside };
        }
      }
    }
  }
  const found = names(indent);
  if (found !== null) return found;
  // Giving back leading blanks only yields names made of blanks (anything longer already failed).
  // Whether such a match exists does not change the result, so it is not searched for.
  return null;
}
