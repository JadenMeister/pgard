// CWE -> PGARD rule map for the real-repository recall measurement (README.md).
// Built from the rules' own standards (`listSourceRules()` / history rules `cwe`): lib.test.ts fails
// when a mapped CWE is not listed by a rule of its entry. The two `assumed` CWEs are the only
// exceptions: the rule detects the weakness (predictable random value) but does not list the CWE.
// A CWE with no entry has no PGARD rule: the case is `no-rule` (inScope=false in cases.json),
// reported separately and never counted as a miss of an existing rule.
//
// One entry = a family name (rows of the aggregate), the CWEs, and the rule ids or id prefixes
// that count as a match for those CWEs.

/** @type {ReadonlyArray<{ family: string, cwes: readonly number[], assumed?: readonly number[], prefixes: readonly string[] }>} */
export const FAMILIES = [
  { family: "sql", cwes: [89], prefixes: ["PG-SQL-"] },
  { family: "xss", cwes: [79], prefixes: ["PG-XSS-"] },
  { family: "command", cwes: [78], prefixes: ["PG-CMD-"] },
  { family: "path", cwes: [22], prefixes: ["PG-PATH-"] },
  { family: "crypto", cwes: [328], prefixes: ["PG-CRYPTO-001"] },
  { family: "crypto", cwes: [327], assumed: [330, 338], prefixes: ["PG-CRYPTO-003"] },
  { family: "crypto", cwes: [321], prefixes: ["PG-CRYPTO-002"] },
  { family: "secret", cwes: [798], prefixes: ["PG-SECRET-", "PG-CRYPTO-002"] },
  { family: "ssrf", cwes: [918], prefixes: ["PG-SSRF-"] },
  { family: "csrf", cwes: [352], prefixes: ["PG-CSRF-"] },
  { family: "cookie", cwes: [614, 1004, 1275], prefixes: ["PG-COOKIE-"] },
  { family: "brute-force", cwes: [307], prefixes: ["PG-BRUTE-"] },
];

const allCwes = (entry) => [...entry.cwes, ...(entry.assumed ?? [])];

export const IN_SCOPE_CWES = FAMILIES.flatMap(allCwes);

export const cweNumber = (cwe) => Number(String(cwe).replace(/^CWE-/i, ""));

/** Entries of a case's CWE list (empty when no rule exists for any of them). */
export function familiesForCwes(cwes) {
  const numbers = cwes.map(cweNumber);
  return FAMILIES.filter((entry) => allCwes(entry).some((cwe) => numbers.includes(cwe)));
}

export const ruleInFamily = (ruleId, family) =>
  family.prefixes.some((prefix) => ruleId.startsWith(prefix));
