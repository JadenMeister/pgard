import type { RawSourceFinding } from "../finding-factory.js";

export const MAX_MYBATIS_FINDINGS_PER_FILE = 25;
/** Findings gathered before the strongest are kept. */
const MAX_COLLECTED = 500;

// A tag may carry a namespace prefix, and an attribute value may contain ">".
const STATEMENT =
  /<(?:[\w.-]+:)?(select|insert|update|delete|sql)\b((?:[^>"']|"[^"]{0,1000}"|'[^']{0,1000}'){0,1000})>/g;
/** A mapper file opens `<mapper ...>`; the `<mapper resource="..."/>` entries of a config do not. */
const MAPPER_OPEN =
  /<(?:[\w.-]+:)?mapper\b(?:[^>"']|"[^"]{0,1000}"|'[^']{0,1000}'){0,1000}(?<!\/)>/;
const NUMERIC_PARAMETER_TYPE =
  /parameterType\s*=\s*["'](?:int|integer|long|short|byte|double|float|boolean|_int|_long|_integer|_double|_boolean|java\.lang\.(?:Integer|Long|Short|Byte|Double|Float|Boolean)|java\.math\.(?:BigDecimal|BigInteger))["']/i;

export interface MybatisAnalysis {
  /** The file is a MyBatis mapper (`<mapper ...>`). */
  isMapper: boolean;
  findings: RawSourceFinding[];
  capped: boolean;
  /** A statement was never closed: the rest of the file was not read. */
  incomplete: boolean;
}

/** Blanks out comments, keeping the length and the line breaks. CDATA text is kept as it is. */
function blankComments(text: string): string {
  if (!text.includes("<!--")) return text;
  return text.replace(/<!\[CDATA\[[\s\S]*?(?:\]\]>|$)|<!--[\s\S]*?(?:-->|$)/g, (match) =>
    match.startsWith("<!--") ? match.replace(/[^\n]/g, " ") : match,
  );
}

/**
 * MyBatis mapper XML: a `${...}` inside `<select>`, `<insert>`, `<update>` or `<delete>` is pasted
 * into the SQL text, while `#{...}` is bound as a parameter. Pure: the text and path decide the
 * result. The XML is scanned with patterns, not parsed, so a DTD or entities are never expanded.
 *
 * A mapper parameter comes from the caller of the mapper method, which this file cannot see, so a
 * `${}` is reported without a traced source: severity high, status suspected, confidence medium.
 * It is lowered to confidence low (medium severity, evidence ending "; inferred") where the text
 * says the value is probably fixed: a numeric `parameterType`, an OGNL static field
 * `${@pkg.Class@FIELD}`, or a `<sql>` fragment (its `${}` is filled in by `<include><property>`).
 */
export function analyzeMybatisXml(text: string, path: string): MybatisAnalysis {
  const clean = blankComments(text);
  if (!MAPPER_OPEN.test(clean)) {
    return { isMapper: false, findings: [], capped: false, incomplete: false };
  }
  const findings: RawSourceFinding[] = [];
  let capped = false;
  let incomplete = false;
  const closers = new Map<string, RegExp>();
  const lineStarts: number[] = [0];
  for (let i = clean.indexOf("\n"); i !== -1; i = clean.indexOf("\n", i + 1))
    lineStarts.push(i + 1);
  const lineAt = (offset: number): number => {
    let low = 0;
    let high = lineStarts.length - 1;
    while (low < high) {
      const mid = (low + high + 1) >> 1;
      if ((lineStarts[mid] as number) <= offset) low = mid;
      else high = mid - 1;
    }
    return low + 1;
  };

  STATEMENT.lastIndex = 0;
  for (;;) {
    const open = STATEMENT.exec(clean);
    if (open === null) break;
    const tag = open[1] as string;
    const attributes = open[2] as string;
    if (attributes.endsWith("/")) continue;
    const bodyStart = open.index + open[0].length;
    let closer = closers.get(tag);
    if (closer === undefined) {
      closer = new RegExp(`</(?:[\\w.-]+:)?${tag}\\s*>`, "g");
      closers.set(tag, closer);
    }
    closer.lastIndex = bodyStart;
    const closeMatch = closer.exec(clean);
    // No closing tag here means none later either (statements do not nest): stop, so a hostile
    // file of unclosed tags costs one scan, and say that the rest was not read.
    if (closeMatch === null) {
      incomplete = true;
      break;
    }
    const close = closeMatch.index;
    STATEMENT.lastIndex = close;
    const id = /\bid\s*=\s*["']([^"']*)["']/.exec(attributes)?.[1] ?? "?";
    const numeric = NUMERIC_PARAMETER_TYPE.test(attributes);
    const seen = new Set<string>();
    for (let at = clean.indexOf("${", bodyStart); at !== -1 && at < close;) {
      const end = clean.indexOf("}", at);
      if (end === -1 || end > close) break;
      const expression = clean.slice(at + 2, end).trim();
      const line = lineAt(at);
      at = clean.indexOf("${", end);
      if (seen.has(expression)) continue;
      seen.add(expression);
      if (findings.length >= MAX_COLLECTED) {
        capped = true;
        break;
      }
      const shown = expression.length > 60 ? `${expression.slice(0, 57)}...` : expression;
      const where = `MyBatis <${tag}${id === "?" ? "" : ` id="${id.slice(0, 40)}"`}> substitutes "\${${shown}}" into the SQL text`;
      let reason: string | null = null;
      if (tag === "sql") reason = "it is in a <sql> fragment, filled in by <include><property>";
      else if (/^@[^@]+@[^@]+$/.test(expression)) reason = "static field reference";
      else if (numeric && /^[A-Za-z_][\w]*$/.test(expression)) {
        reason = "the parameterType is numeric or boolean";
      }
      const cause = `${tag}:${id}:${expression}`;
      if (reason === null) {
        findings.push({
          ruleId: "PG-SQL-005",
          path,
          line,
          severity: "high",
          status: "suspected",
          confidence: "medium",
          evidence: `${where} (a mapper parameter comes from the caller; use #{} to bind it)`,
          cause,
        });
      } else {
        findings.push({
          ruleId: "PG-SQL-005",
          path,
          line,
          severity: "medium",
          status: "suspected",
          confidence: "low",
          evidence: `${where}; ${reason}; inferred`,
          cause,
        });
      }
    }
    if (capped) break;
  }
  // The cap keeps the strongest findings (confidence medium before low), not the first ones.
  const rank = (finding: RawSourceFinding): number => (finding.confidence === "low" ? 0 : 1);
  const kept = [...findings]
    .sort((a, b) => rank(b) - rank(a) || a.line - b.line)
    .slice(0, MAX_MYBATIS_FINDINGS_PER_FILE)
    .sort((a, b) => a.line - b.line);
  return {
    isMapper: true,
    findings: kept,
    capped: capped || findings.length > MAX_MYBATIS_FINDINGS_PER_FILE,
    incomplete,
  };
}
