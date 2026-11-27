// CWE -> PGARD rule family map for the real-repository recall measurement (README.md).
// A finding "matches" a case when its rule id starts with one of the family's prefixes and the
// case lists one of the family's CWEs. Rule ids are verified against SOURCE_RULES and the secret
// patterns (PG-SECRET-*, found by the working-tree secrets pass of a code-only scan).
// A CWE not listed here has no PGARD rule family: such a case is out of scope (inScope=false in
// cases.json), and it is still measured and counted in the "all" numbers, never hidden.

/** @type {ReadonlyArray<{ family: string, cwes: readonly number[], prefixes: readonly string[] }>} */
export const FAMILIES = [
  { family: "sql", cwes: [89], prefixes: ["PG-SQL-"] },
  { family: "xss", cwes: [79], prefixes: ["PG-XSS-"] },
  { family: "command", cwes: [78, 77], prefixes: ["PG-CMD-"] },
  { family: "path", cwes: [22], prefixes: ["PG-PATH-"] },
  { family: "crypto", cwes: [327, 328, 330, 326, 321], prefixes: ["PG-CRYPTO-"] },
  { family: "secret", cwes: [798], prefixes: ["PG-SECRET-"] },
  { family: "ssrf", cwes: [918], prefixes: ["PG-SSRF-"] },
  { family: "csrf", cwes: [352], prefixes: ["PG-CSRF-"] },
  { family: "cookie", cwes: [614, 1004], prefixes: ["PG-COOKIE-"] },
  { family: "auth", cwes: [287, 306], prefixes: ["PG-AUTH-"] },
  { family: "brute-force", cwes: [307], prefixes: ["PG-BRUTE-"] },
  { family: "config", cwes: [16, 1188], prefixes: ["PG-CONF-"] },
];

export const IN_SCOPE_CWES = FAMILIES.flatMap((entry) => entry.cwes);

export const cweNumber = (cwe) => Number(String(cwe).replace(/^CWE-/i, ""));

/** Families of a case's CWE list (usually one; empty when no rule family exists). */
export function familiesForCwes(cwes) {
  const numbers = cwes.map(cweNumber);
  return FAMILIES.filter((entry) => entry.cwes.some((cwe) => numbers.includes(cwe)));
}

export const ruleInFamily = (ruleId, family) =>
  family.prefixes.some((prefix) => ruleId.startsWith(prefix));
