import {
  defineRule,
  type RuleDefinition,
  type RuleDescriptor,
  type RuleLanguage,
} from "@pgard/findings";

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
    standards: { owasp: ["A05:2025"], cwe: ["CWE-89"], cert: [] },
    rationale: {
      en: "Input can change the structure of the SQL statement (read, modify or delete data).",
      ko: "입력이 SQL 문의 구조를 바꿔 데이터를 읽거나 수정하거나 삭제할 수 있습니다.",
    },
    remediation: {
      en: "Pass values as bound parameters (e.g. `query('... WHERE id = $1', [id])`) instead of building SQL text.",
      ko: "SQL 문자열을 직접 만들지 말고 값을 바인딩된 매개변수로 전달하세요(예: `query('... WHERE id = $1', [id])`).",
    },
  },
  {
    id: "PG-SQL-002",
    title: "Prisma unsafe raw query with dynamic SQL",
    category: "injection",
    defaultSeverity: "high",
    scope: "code",
    languages: JS_TS,
    standards: { owasp: ["A05:2025"], cwe: ["CWE-89"], cert: [] },
    rationale: {
      en: "Input can change the structure of the raw SQL statement.",
      ko: "입력이 raw SQL 문의 구조를 바꿀 수 있습니다.",
    },
    remediation: {
      en: "Use the tagged template `$queryRaw` / `$executeRaw` or `Prisma.sql`, or pass values as extra parameters to the Unsafe variant.",
      ko: "태그드 템플릿 `$queryRaw` / `$executeRaw`나 `Prisma.sql`을 사용하거나, Unsafe 변형에는 값을 추가 매개변수로 전달하세요.",
    },
  },
  {
    id: "PG-SQL-003",
    title: "Go database/sql query built with fmt.Sprintf or concatenation",
    category: "injection",
    defaultSeverity: "high",
    scope: "code",
    languages: ["go"],
    standards: { owasp: ["A05:2025"], cwe: ["CWE-89"], cert: [] },
    rationale: {
      en: "Input can change the structure of the SQL statement.",
      ko: "입력이 SQL 문의 구조를 바꿀 수 있습니다.",
    },
    remediation: {
      en: "Use placeholders (`?` or `$1`) and pass values as arguments to Query/Exec.",
      ko: "플레이스홀더(`?` 또는 `$1`)를 사용하고 값은 Query/Exec의 인자로 전달하세요.",
    },
  },
  {
    id: "PG-SQL-004",
    title: "GORM raw SQL or condition built with fmt.Sprintf or concatenation",
    category: "injection",
    defaultSeverity: "high",
    scope: "code",
    languages: ["go"],
    standards: { owasp: ["A05:2025"], cwe: ["CWE-89"], cert: [] },
    rationale: {
      en: "Input can change the structure of the SQL statement.",
      ko: "입력이 SQL 문의 구조를 바꿀 수 있습니다.",
    },
    remediation: {
      en: 'Use GORM placeholders, e.g. `db.Where("name = ?", name)`, `db.Raw("... ?", v)`.',
      ko: 'GORM 플레이스홀더를 사용하세요. 예: `db.Where("name = ?", name)`, `db.Raw("... ?", v)`.',
    },
  },
  {
    id: "PG-XSS-001",
    title: "Dynamic HTML written to innerHTML/outerHTML/document.write",
    category: "xss",
    defaultSeverity: "high",
    scope: "code",
    languages: JS_TS,
    standards: { owasp: ["A05:2025"], cwe: ["CWE-79"], cert: [] },
    rationale: {
      en: "Untrusted HTML can run script in the user's browser.",
      ko: "신뢰할 수 없는 HTML이 사용자의 브라우저에서 스크립트를 실행할 수 있습니다.",
    },
    remediation: {
      en: "Use textContent, or sanitize with a maintained sanitizer (e.g. DOMPurify) before inserting HTML.",
      ko: "textContent를 사용하거나, HTML을 삽입하기 전에 관리되는 sanitizer(예: DOMPurify)로 정화하세요.",
    },
  },
  {
    id: "PG-XSS-002",
    title: "Dynamic HTML passed to React dangerouslySetInnerHTML",
    category: "xss",
    defaultSeverity: "high",
    scope: "code",
    languages: ["react"],
    standards: { owasp: ["A05:2025"], cwe: ["CWE-79"], cert: [] },
    rationale: {
      en: "Untrusted HTML can run script in the user's browser.",
      ko: "신뢰할 수 없는 HTML이 사용자의 브라우저에서 스크립트를 실행할 수 있습니다.",
    },
    remediation: {
      en: "Render text through JSX, or sanitize the HTML (e.g. DOMPurify) first.",
      ko: "JSX로 텍스트를 렌더링하거나, 먼저 HTML을 정화하세요(예: DOMPurify).",
    },
  },
  {
    id: "PG-XSS-003",
    title: "Dynamic HTML bound with Vue v-html",
    category: "xss",
    defaultSeverity: "high",
    scope: "code",
    languages: ["vue"],
    standards: { owasp: ["A05:2025"], cwe: ["CWE-79"], cert: [] },
    rationale: {
      en: "Untrusted HTML can run script in the user's browser.",
      ko: "신뢰할 수 없는 HTML이 사용자의 브라우저에서 스크립트를 실행할 수 있습니다.",
    },
    remediation: {
      en: "Use text interpolation (`{{ }}`), or sanitize the HTML before binding it.",
      ko: "텍스트 보간(`{{ }}`)을 사용하거나, HTML을 바인딩하기 전에 정화하세요.",
    },
  },
  {
    id: "PG-SSRF-001",
    title: "Server-side HTTP request to a URL from request input",
    category: "ssrf",
    defaultSeverity: "high",
    scope: "code",
    languages: ["javascript", "typescript", "go"],
    standards: { owasp: ["A01:2025"], cwe: ["CWE-918"], cert: [] },
    rationale: {
      en: "The server can be made to call internal services or cloud metadata endpoints.",
      ko: "서버가 내부 서비스나 클라우드 메타데이터 엔드포인트를 호출하도록 유도될 수 있습니다.",
    },
    remediation: {
      en: "Allow only known hosts/schemes (allowlist), resolve and block private addresses, and do not forward raw user URLs.",
      ko: "알려진 호스트와 스킴만 허용(allowlist)하고, 주소를 해석해 사설 주소를 차단하며, 사용자가 준 URL을 그대로 전달하지 마세요.",
    },
  },
  {
    id: "PG-CMD-001",
    title: "Shell command built from dynamic strings (child_process)",
    category: "command_execution",
    defaultSeverity: "high",
    scope: "code",
    languages: JS_TS,
    standards: {
      owasp: ["A05:2025"],
      cwe: ["CWE-78"],
      cert: [{ kind: "via-cwe", id: "IDS07-J", cwe: "CWE-78" }],
    },
    rationale: {
      en: "Input can inject additional shell commands.",
      ko: "입력이 추가 셸 명령을 주입할 수 있습니다.",
    },
    remediation: {
      en: "Use execFile/spawn with an argument array and no shell; validate arguments against an allowlist.",
      ko: "셸 없이 인자 배열과 함께 execFile/spawn을 사용하고, 인자는 allowlist로 검증하세요.",
    },
  },
  {
    id: "PG-CMD-002",
    title: "Go exec.Command with a shell or dynamic program",
    category: "command_execution",
    defaultSeverity: "high",
    scope: "code",
    languages: ["go"],
    standards: {
      owasp: ["A05:2025"],
      cwe: ["CWE-78"],
      cert: [{ kind: "via-cwe", id: "IDS07-J", cwe: "CWE-78" }],
    },
    rationale: {
      en: "Input can inject additional shell commands.",
      ko: "입력이 추가 셸 명령을 주입할 수 있습니다.",
    },
    remediation: {
      en: 'Call the program directly with separate arguments (`exec.Command("git", "log")`), never via `sh -c`.',
      ko: '프로그램을 인자를 나누어 직접 호출하고(`exec.Command("git", "log")`), `sh -c`를 거치지 마세요.',
    },
  },
  {
    id: "PG-PATH-001",
    title: "File path from request input used in file read/download",
    category: "file_handling",
    defaultSeverity: "high",
    scope: "code",
    languages: ["javascript", "typescript", "go"],
    standards: { owasp: ["A01:2025"], cwe: ["CWE-22"], cert: [] },
    rationale: {
      en: "`../` sequences can read or serve files outside the intended directory.",
      ko: "`../` 시퀀스로 의도한 디렉터리 밖의 파일을 읽거나 내려받게 할 수 있습니다.",
    },
    remediation: {
      en: "Reduce the input to a basename or id, resolve against a fixed root and verify the result stays inside it.",
      ko: "입력을 basename이나 id로 줄이고, 고정된 루트를 기준으로 해석한 뒤 결과가 그 루트 안에 있는지 확인하세요.",
    },
  },
  {
    id: "PG-CRYPTO-001",
    title: "Weak hash (MD5/SHA-1) used for passwords",
    category: "cryptography",
    defaultSeverity: "high",
    scope: "code",
    languages: ["javascript", "typescript", "go"],
    standards: { owasp: ["A04:2025"], cwe: ["CWE-916", "CWE-328"], cert: [] },
    rationale: {
      en: "Password hashes can be cracked quickly after a database leak.",
      ko: "데이터베이스가 유출되면 비밀번호 해시를 빠르게 풀 수 있습니다.",
    },
    remediation: {
      en: "Hash passwords with bcrypt, scrypt or Argon2id with a per-user salt.",
      ko: "사용자마다 다른 salt를 적용해 bcrypt, scrypt 또는 Argon2id로 비밀번호를 해시하세요.",
    },
  },
  {
    id: "PG-CRYPTO-002",
    title: "Hardcoded cryptographic key or signing secret",
    category: "cryptography",
    defaultSeverity: "high",
    scope: "code",
    languages: ["javascript", "typescript", "go"],
    standards: {
      owasp: ["A04:2025"],
      cwe: ["CWE-321", "CWE-798"],
      cert: [{ kind: "via-cwe", id: "MSC03-J", cwe: "CWE-798" }],
    },
    rationale: {
      en: "Anyone with the source can decrypt data or forge tokens.",
      ko: "소스 코드를 가진 사람은 누구나 데이터를 복호화하거나 토큰을 위조할 수 있습니다.",
    },
    remediation: {
      en: "Load keys from a secret store or environment at runtime and rotate the exposed key.",
      ko: "키는 실행 시점에 비밀 저장소나 환경에서 불러오고, 노출된 키는 교체(rotate)하세요.",
    },
  },
  {
    id: "PG-CRYPTO-003",
    title: "Broken or deprecated cipher",
    category: "cryptography",
    defaultSeverity: "medium",
    scope: "code",
    languages: JS_TS,
    standards: {
      owasp: ["A04:2025"],
      cwe: ["CWE-327"],
      cert: [{ kind: "via-cwe", id: "MSC02-J", cwe: "CWE-327" }],
    },
    rationale: {
      en: "Encrypted data may be recoverable or tampered with.",
      ko: "암호화된 데이터가 복구되거나 변조될 수 있습니다.",
    },
    remediation: {
      en: "Use an AEAD cipher such as AES-256-GCM via createCipheriv with a random IV.",
      ko: "무작위 IV와 함께 createCipheriv로 AES-256-GCM 같은 AEAD 암호를 사용하세요.",
    },
  },
  {
    id: "PG-AUTH-001",
    title: "Password stored without hashing",
    category: "cryptography",
    defaultSeverity: "high",
    scope: "code",
    languages: JS_TS,
    standards: { owasp: ["A04:2025"], cwe: ["CWE-256"], cert: [] },
    rationale: {
      en: "A database leak exposes every user's password.",
      ko: "데이터베이스가 유출되면 모든 사용자의 비밀번호가 노출됩니다.",
    },
    remediation: {
      en: "Hash the password with bcrypt, scrypt or Argon2id before storing it.",
      ko: "저장하기 전에 bcrypt, scrypt 또는 Argon2id로 비밀번호를 해시하세요.",
    },
  },
  {
    id: "PG-COOKIE-001",
    title: "Session or auth cookie without HttpOnly/Secure/SameSite",
    category: "misconfiguration",
    defaultSeverity: "medium",
    scope: "code",
    languages: ["javascript", "typescript", "go"],
    standards: { owasp: ["A02:2025"], cwe: ["CWE-1004", "CWE-614"], cert: [] },
    rationale: {
      en: "Cookies may be read by scripts, sent over plain HTTP or sent cross-site.",
      ko: "쿠키를 스크립트가 읽거나, 평문 HTTP로 전송하거나, 다른 사이트로 보낼 수 있습니다.",
    },
    remediation: {
      en: "Set httpOnly, secure and sameSite ('lax' or 'strict') on session cookies.",
      ko: "세션 쿠키에 httpOnly, secure, sameSite('lax' 또는 'strict')를 설정하세요.",
    },
  },
  {
    id: "PG-CSRF-001",
    title: "Cookie-authenticated state-changing routes without visible CSRF protection",
    category: "csrf",
    defaultSeverity: "medium",
    scope: "code",
    languages: JS_TS,
    standards: { owasp: ["A01:2025"], cwe: ["CWE-352"], cert: [] },
    rationale: {
      en: "Another site may trigger state changes with the user's cookies.",
      ko: "다른 사이트가 사용자의 쿠키로 상태 변경 요청을 일으킬 수 있습니다.",
    },
    remediation: {
      en: "Use CSRF tokens (or SameSite=strict cookies plus Origin checks) for cookie-authenticated POST/PUT/PATCH/DELETE routes.",
      ko: "쿠키로 인증하는 POST/PUT/PATCH/DELETE 라우트에는 CSRF 토큰(또는 SameSite=strict 쿠키와 Origin 검사)을 사용하세요.",
    },
  },
  {
    id: "PG-BRUTE-001",
    title: "Login or password reset route without visible rate limiting",
    category: "brute_force",
    defaultSeverity: "medium",
    scope: "code",
    languages: JS_TS,
    standards: { owasp: ["A07:2025"], cwe: ["CWE-307"], cert: [] },
    rationale: {
      en: "Passwords or reset codes can be guessed by automated requests.",
      ko: "자동화된 요청으로 비밀번호나 재설정 코드를 추측할 수 있습니다.",
    },
    remediation: {
      en: "Add per-account and per-IP rate limiting or lockout (e.g. express-rate-limit) to authentication routes.",
      ko: "인증 라우트에 계정별·IP별 요청 제한이나 잠금(예: express-rate-limit)을 추가하세요.",
    },
  },
] as const satisfies readonly RuleDefinition[];

export type SourceRuleId = (typeof SOURCE_RULES)[number]["id"];

const DESCRIPTORS: readonly RuleDescriptor[] = SOURCE_RULES.map(defineRule);
const RULES_BY_ID = new Map<string, RuleDescriptor>(DESCRIPTORS.map((rule) => [rule.id, rule]));

export function getRule(id: SourceRuleId): RuleDescriptor {
  const rule = RULES_BY_ID.get(id);
  if (!rule) {
    throw new Error(`Unknown rule ${id}`);
  }
  return rule;
}

export function listSourceRules(): RuleDescriptor[] {
  return SOURCE_RULES.map(defineRule);
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
