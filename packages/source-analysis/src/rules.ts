import type { RuleDescriptor, RuleLanguage } from "@pgard/findings";

export type { RuleDescriptor, RuleLanguage } from "@pgard/findings";

const JS_TS: RuleLanguage[] = ["javascript", "typescript"];

export const SOURCE_RULES = [
  {
    id: "PG-SQL-001",
    title: "SQL built from dynamic strings in pg/mysql2 query",
    category: "injection",
    defaultSeverity: "high",
    scope: "code",
    languages: JS_TS,
    cwe: ["CWE-89"],
    owasp: ["A05:2025"],
    impact: "Input can change the structure of the SQL statement (read, modify or delete data).",
    recommendation:
      "Pass values as bound parameters (e.g. `query('... WHERE id = $1', [id])`) instead of building SQL text.",
  },
  {
    id: "PG-SQL-002",
    title: "Prisma unsafe raw query with dynamic SQL",
    category: "injection",
    defaultSeverity: "high",
    scope: "code",
    languages: JS_TS,
    cwe: ["CWE-89"],
    owasp: ["A05:2025"],
    impact: "Input can change the structure of the raw SQL statement.",
    recommendation:
      "Use the tagged template `$queryRaw` / `$executeRaw` or `Prisma.sql`, or pass values as extra parameters to the Unsafe variant.",
  },
  {
    id: "PG-SQL-003",
    title: "Go database/sql query built with fmt.Sprintf or concatenation",
    category: "injection",
    defaultSeverity: "high",
    scope: "code",
    languages: ["go"],
    cwe: ["CWE-89"],
    owasp: ["A05:2025"],
    impact: "Input can change the structure of the SQL statement.",
    recommendation: "Use placeholders (`?` or `$1`) and pass values as arguments to Query/Exec.",
  },
  {
    id: "PG-SQL-004",
    title: "GORM raw SQL or condition built with fmt.Sprintf or concatenation",
    category: "injection",
    defaultSeverity: "high",
    scope: "code",
    languages: ["go"],
    cwe: ["CWE-89"],
    owasp: ["A05:2025"],
    impact: "Input can change the structure of the SQL statement.",
    recommendation:
      'Use GORM placeholders, e.g. `db.Where("name = ?", name)`, `db.Raw("... ?", v)`.',
  },
  {
    id: "PG-XSS-001",
    title: "Dynamic HTML written to innerHTML/outerHTML/document.write",
    category: "xss",
    defaultSeverity: "high",
    scope: "code",
    languages: JS_TS,
    cwe: ["CWE-79"],
    owasp: ["A05:2025"],
    impact: "Untrusted HTML can run script in the user's browser.",
    recommendation:
      "Use textContent, or sanitize with a maintained sanitizer (e.g. DOMPurify) before inserting HTML.",
  },
  {
    id: "PG-XSS-002",
    title: "Dynamic HTML passed to React dangerouslySetInnerHTML",
    category: "xss",
    defaultSeverity: "high",
    scope: "code",
    languages: ["react"],
    cwe: ["CWE-79"],
    owasp: ["A05:2025"],
    impact: "Untrusted HTML can run script in the user's browser.",
    recommendation: "Render text through JSX, or sanitize the HTML (e.g. DOMPurify) first.",
  },
  {
    id: "PG-XSS-003",
    title: "Dynamic HTML bound with Vue v-html",
    category: "xss",
    defaultSeverity: "high",
    scope: "code",
    languages: ["vue"],
    cwe: ["CWE-79"],
    owasp: ["A05:2025"],
    impact: "Untrusted HTML can run script in the user's browser.",
    recommendation: "Use text interpolation (`{{ }}`), or sanitize the HTML before binding it.",
  },
  {
    id: "PG-SSRF-001",
    title: "Server-side HTTP request to a URL from request input",
    category: "ssrf",
    defaultSeverity: "high",
    scope: "code",
    languages: ["javascript", "typescript", "go"],
    cwe: ["CWE-918"],
    owasp: ["A01:2025"],
    impact: "The server can be made to call internal services or cloud metadata endpoints.",
    recommendation:
      "Allow only known hosts/schemes (allowlist), resolve and block private addresses, and do not forward raw user URLs.",
  },
  {
    id: "PG-CMD-001",
    title: "Shell command built from dynamic strings (child_process)",
    category: "command_execution",
    defaultSeverity: "high",
    scope: "code",
    languages: JS_TS,
    cwe: ["CWE-78"],
    owasp: ["A05:2025"],
    impact: "Input can inject additional shell commands.",
    recommendation:
      "Use execFile/spawn with an argument array and no shell; validate arguments against an allowlist.",
  },
  {
    id: "PG-CMD-002",
    title: "Go exec.Command with a shell or dynamic program",
    category: "command_execution",
    defaultSeverity: "high",
    scope: "code",
    languages: ["go"],
    cwe: ["CWE-78"],
    owasp: ["A05:2025"],
    impact: "Input can inject additional shell commands.",
    recommendation:
      'Call the program directly with separate arguments (`exec.Command("git", "log")`), never via `sh -c`.',
  },
  {
    id: "PG-PATH-001",
    title: "File path from request input used in file read/download",
    category: "file_handling",
    defaultSeverity: "high",
    scope: "code",
    languages: ["javascript", "typescript", "go"],
    cwe: ["CWE-22"],
    owasp: ["A01:2025"],
    impact: "`../` sequences can read or serve files outside the intended directory.",
    recommendation:
      "Reduce the input to a basename or id, resolve against a fixed root and verify the result stays inside it.",
  },
  {
    id: "PG-CRYPTO-001",
    title: "Weak hash (MD5/SHA-1) used for passwords",
    category: "cryptography",
    defaultSeverity: "high",
    scope: "code",
    languages: ["javascript", "typescript", "go"],
    cwe: ["CWE-916", "CWE-328"],
    owasp: ["A04:2025"],
    impact: "Password hashes can be cracked quickly after a database leak.",
    recommendation: "Hash passwords with bcrypt, scrypt or Argon2id with a per-user salt.",
  },
  {
    id: "PG-CRYPTO-002",
    title: "Hardcoded cryptographic key or signing secret",
    category: "cryptography",
    defaultSeverity: "high",
    scope: "code",
    languages: ["javascript", "typescript", "go"],
    cwe: ["CWE-321", "CWE-798"],
    owasp: ["A04:2025"],
    impact: "Anyone with the source can decrypt data or forge tokens.",
    recommendation:
      "Load keys from a secret store or environment at runtime and rotate the exposed key.",
  },
  {
    id: "PG-CRYPTO-003",
    title: "Broken or deprecated cipher",
    category: "cryptography",
    defaultSeverity: "medium",
    scope: "code",
    languages: JS_TS,
    cwe: ["CWE-327"],
    owasp: ["A04:2025"],
    impact: "Encrypted data may be recoverable or tampered with.",
    recommendation: "Use an AEAD cipher such as AES-256-GCM via createCipheriv with a random IV.",
  },
  {
    id: "PG-AUTH-001",
    title: "Password stored without hashing",
    category: "cryptography",
    defaultSeverity: "high",
    scope: "code",
    languages: JS_TS,
    cwe: ["CWE-256"],
    owasp: ["A04:2025"],
    impact: "A database leak exposes every user's password.",
    recommendation: "Hash the password with bcrypt, scrypt or Argon2id before storing it.",
  },
  {
    id: "PG-COOKIE-001",
    title: "Session or auth cookie without HttpOnly/Secure/SameSite",
    category: "misconfiguration",
    defaultSeverity: "medium",
    scope: "code",
    languages: ["javascript", "typescript", "go"],
    cwe: ["CWE-1004", "CWE-614"],
    owasp: ["A02:2025"],
    impact: "Cookies may be read by scripts, sent over plain HTTP or sent cross-site.",
    recommendation: "Set httpOnly, secure and sameSite ('lax' or 'strict') on session cookies.",
  },
  {
    id: "PG-CSRF-001",
    title: "Cookie-authenticated state-changing routes without visible CSRF protection",
    category: "csrf",
    defaultSeverity: "medium",
    scope: "code",
    languages: JS_TS,
    cwe: ["CWE-352"],
    owasp: ["A01:2025"],
    impact: "Another site may trigger state changes with the user's cookies.",
    recommendation:
      "Use CSRF tokens (or SameSite=strict cookies plus Origin checks) for cookie-authenticated POST/PUT/PATCH/DELETE routes.",
  },
  {
    id: "PG-BRUTE-001",
    title: "Login or password reset route without visible rate limiting",
    category: "brute_force",
    defaultSeverity: "medium",
    scope: "code",
    languages: JS_TS,
    cwe: ["CWE-307"],
    owasp: ["A07:2025"],
    impact: "Passwords or reset codes can be guessed by automated requests.",
    recommendation:
      "Add per-account and per-IP rate limiting or lockout (e.g. express-rate-limit) to authentication routes.",
  },
] as const satisfies readonly RuleDescriptor[];

export type SourceRuleId = (typeof SOURCE_RULES)[number]["id"];

const RULES_BY_ID = new Map<string, RuleDescriptor>(SOURCE_RULES.map((rule) => [rule.id, rule]));

export function getRule(id: SourceRuleId): RuleDescriptor {
  const rule = RULES_BY_ID.get(id);
  if (!rule) {
    throw new Error(`Unknown rule ${id}`);
  }
  return rule;
}

export function listSourceRules(): RuleDescriptor[] {
  return SOURCE_RULES.map((rule) => ({
    ...rule,
    languages: [...rule.languages],
    cwe: [...rule.cwe],
    owasp: [...rule.owasp],
  }));
}

export const JS_RULE_IDS: SourceRuleId[] = SOURCE_RULES.filter((rule) =>
  rule.languages.some((language: RuleLanguage) =>
    ["javascript", "typescript", "react"].includes(language),
  ),
).map((rule) => rule.id);

export const GO_RULE_IDS: SourceRuleId[] = SOURCE_RULES.filter((rule) =>
  rule.languages.some((language: RuleLanguage) => language === "go"),
).map((rule) => rule.id);

export const VUE_RULE_IDS: SourceRuleId[] = ["PG-XSS-003"];
