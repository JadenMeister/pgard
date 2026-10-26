import type {
  Confidence,
  FindingCategory,
  FindingReferences,
  FindingStatus,
  RuleMetadata,
  Severity,
} from "@pgard/findings";

/** A local HTTP rule as written: identity plus the explanatory metadata. */
export interface WebRuleDefinition extends RuleMetadata {
  id: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
}

/**
 * `impact`, `recommendation` and `references` are the English values derived from `metadata`;
 * findings use them unchanged.
 */
export interface WebRule {
  id: string;
  title: string;
  category: FindingCategory;
  severity: Severity;
  status: FindingStatus;
  confidence: Confidence;
  impact: string;
  recommendation: string;
  references: FindingReferences;
  metadata: RuleMetadata;
}

const MISCONFIGURATION = "A02:2025";

function rule(definition: WebRuleDefinition): WebRule {
  const { standards, rationale, remediation, examples, ...identity } = definition;
  return {
    ...identity,
    impact: rationale.en,
    recommendation: remediation.en,
    references: { cwe: [...standards.cwe], owasp: [...standards.owasp], cve: [] },
    metadata: {
      standards,
      rationale,
      remediation,
      ...(examples === undefined ? {} : { examples }),
    },
  };
}

/**
 * Anonymous local HTTP rules. A missing header is reported as informational/suspected and never
 * as proof that the service is vulnerable.
 */
export const WEB_RULES = {
  missingCsp: rule({
    id: "PG-WEB-001",
    title: "Content-Security-Policy header is missing",
    category: "misconfiguration",
    severity: "low",
    status: "informational",
    confidence: "high",
    standards: { owasp: [MISCONFIGURATION], cwe: ["CWE-693"], cert: [] },
    rationale: {
      en: "Without a CSP, an XSS flaw elsewhere is easier to exploit. This alone is not a vulnerability.",
      ko: "CSP가 없으면 다른 곳의 XSS 결함을 악용하기 더 쉬워집니다. 이것만으로는 취약점이 아닙니다.",
    },
    remediation: {
      en: "Send a Content-Security-Policy that restricts script sources for HTML responses.",
      ko: "HTML 응답에 스크립트 출처를 제한하는 Content-Security-Policy를 보내세요.",
    },
  }),
  missingFrameProtection: rule({
    id: "PG-WEB-002",
    title: "Clickjacking protection header is missing",
    category: "misconfiguration",
    severity: "low",
    status: "informational",
    confidence: "high",
    standards: { owasp: [MISCONFIGURATION], cwe: ["CWE-1021"], cert: [] },
    rationale: {
      en: "Pages may be framed by other sites, which can enable clickjacking on sensitive actions.",
      ko: "다른 사이트가 이 페이지를 프레임으로 삽입할 수 있어, 민감한 동작에 클릭재킹이 가능해질 수 있습니다.",
    },
    remediation: {
      en: "Send CSP frame-ancestors (or X-Frame-Options: DENY/SAMEORIGIN).",
      ko: "CSP frame-ancestors(또는 X-Frame-Options: DENY/SAMEORIGIN)를 보내세요.",
    },
  }),
  missingNoSniff: rule({
    id: "PG-WEB-003",
    title: "X-Content-Type-Options: nosniff is missing",
    category: "misconfiguration",
    severity: "info",
    status: "informational",
    confidence: "high",
    standards: { owasp: [MISCONFIGURATION], cwe: ["CWE-693"], cert: [] },
    rationale: {
      en: "Browsers may MIME-sniff responses, which can turn uploaded content into script.",
      ko: "브라우저가 응답의 MIME 타입을 추측(sniffing)해 업로드된 콘텐츠를 스크립트로 실행할 수 있습니다.",
    },
    remediation: {
      en: "Send X-Content-Type-Options: nosniff on all responses.",
      ko: "모든 응답에 X-Content-Type-Options: nosniff를 보내세요.",
    },
  }),
  missingReferrerPolicy: rule({
    id: "PG-WEB-004",
    title: "Referrer-Policy header is missing",
    category: "misconfiguration",
    severity: "info",
    status: "informational",
    confidence: "high",
    standards: { owasp: [MISCONFIGURATION], cwe: ["CWE-200"], cert: [] },
    rationale: {
      en: "Full URLs (possibly with identifiers) may leak to third parties via the Referer header.",
      ko: "전체 URL(식별자가 포함될 수 있음)이 Referer 헤더를 통해 제3자에게 유출될 수 있습니다.",
    },
    remediation: {
      en: "Send Referrer-Policy: strict-origin-when-cross-origin or stricter.",
      ko: "Referrer-Policy: strict-origin-when-cross-origin 또는 더 엄격한 값을 보내세요.",
    },
  }),
  cookieWithoutHttpOnly: rule({
    id: "PG-WEB-005",
    title: "Cookie is set without HttpOnly",
    category: "misconfiguration",
    severity: "low",
    status: "suspected",
    confidence: "medium",
    standards: { owasp: [MISCONFIGURATION], cwe: ["CWE-1004"], cert: [] },
    rationale: {
      en: "If the cookie carries a session, script injected through XSS can read it.",
      ko: "쿠키가 세션을 담고 있다면 XSS로 주입된 스크립트가 이를 읽을 수 있습니다.",
    },
    remediation: {
      en: "Set HttpOnly on session and authentication cookies.",
      ko: "세션·인증 쿠키에 HttpOnly를 설정하세요.",
    },
  }),
  cookieWithoutSameSite: rule({
    id: "PG-WEB-006",
    title: "Cookie is set without SameSite",
    category: "csrf",
    severity: "low",
    status: "suspected",
    confidence: "medium",
    standards: { owasp: [MISCONFIGURATION], cwe: ["CWE-1275"], cert: [] },
    rationale: {
      en: "Browser defaults vary; without SameSite, cross-site requests may carry the cookie.",
      ko: "브라우저마다 기본값이 달라서, SameSite가 없으면 다른 사이트의 요청에 쿠키가 실릴 수 있습니다.",
    },
    remediation: {
      en: "Set SameSite=Lax or Strict explicitly on session cookies.",
      ko: "세션 쿠키에 SameSite=Lax 또는 Strict를 명시적으로 설정하세요.",
    },
  }),
  cookieWithoutSecure: rule({
    id: "PG-WEB-007",
    title: "Cookie is set without Secure",
    category: "misconfiguration",
    severity: "info",
    status: "informational",
    confidence: "medium",
    standards: { owasp: [MISCONFIGURATION], cwe: ["CWE-614"], cert: [] },
    rationale: {
      en: "Expected on plain-http loopback; make sure production (HTTPS) sets Secure so the cookie is never sent over HTTP.",
      ko: "평문 http 루프백에서는 예상되는 결과입니다. 운영 환경(HTTPS)에서는 쿠키가 HTTP로 절대 전송되지 않도록 Secure를 설정했는지 확인하세요.",
    },
    remediation: {
      en: "Set Secure on cookies in HTTPS deployments.",
      ko: "HTTPS 배포에서는 쿠키에 Secure를 설정하세요.",
    },
  }),
  corsWildcardWithCredentials: rule({
    id: "PG-WEB-008",
    title: "CORS allows any origin together with credentials",
    category: "misconfiguration",
    severity: "medium",
    status: "suspected",
    confidence: "medium",
    standards: { owasp: [MISCONFIGURATION], cwe: ["CWE-942"], cert: [] },
    rationale: {
      en: "Indicates a permissive CORS setup; combined with origin reflection it can expose user data.",
      ko: "느슨한 CORS 설정을 뜻하며, origin 반사와 함께 쓰이면 사용자 데이터가 노출될 수 있습니다.",
    },
    remediation: {
      en: "Allow only specific trusted origins when credentials are enabled.",
      ko: "자격 증명을 켠 경우에는 신뢰하는 특정 origin만 허용하세요.",
    },
  }),
  corsReflectedOrigin: rule({
    id: "PG-WEB-009",
    title: "CORS reflects an arbitrary Origin with credentials",
    category: "access_control",
    severity: "high",
    status: "suspected",
    confidence: "medium",
    standards: { owasp: ["A01:2025"], cwe: ["CWE-942"], cert: [] },
    rationale: {
      en: "Any website a logged-in user visits may read authenticated responses from this service.",
      ko: "로그인한 사용자가 방문한 아무 웹사이트나 이 서비스의 인증된 응답을 읽을 수 있습니다.",
    },
    remediation: {
      en: "Validate Origin against an allowlist; never echo it back with credentials enabled.",
      ko: "Origin을 allowlist와 대조해 검증하고, 자격 증명을 켠 상태에서 값을 그대로 되돌려 주지 마세요.",
    },
  }),
  versionDisclosure: rule({
    id: "PG-WEB-010",
    title: "Server software version is disclosed",
    category: "misconfiguration",
    severity: "low",
    status: "confirmed",
    confidence: "high",
    standards: { owasp: [MISCONFIGURATION], cwe: ["CWE-200"], cert: [] },
    rationale: {
      en: "Exact versions help attackers pick known exploits.",
      ko: "정확한 버전을 알면 공격자가 알려진 익스플로잇을 고르기 쉬워집니다.",
    },
    remediation: {
      en: "Remove version details from Server / X-Powered-By headers.",
      ko: "Server / X-Powered-By 헤더에서 버전 정보를 제거하세요.",
    },
  }),
  directoryListing: rule({
    id: "PG-WEB-011",
    title: "Directory listing is enabled",
    category: "misconfiguration",
    severity: "medium",
    status: "confirmed",
    confidence: "high",
    standards: { owasp: [MISCONFIGURATION], cwe: ["CWE-548"], cert: [] },
    rationale: {
      en: "File names and unintended files may be browsed and downloaded.",
      ko: "파일 이름과 의도하지 않은 파일을 둘러보고 내려받을 수 있습니다.",
    },
    remediation: {
      en: "Disable automatic directory indexes in the web server or static file middleware.",
      ko: "웹 서버나 정적 파일 미들웨어의 자동 디렉터리 인덱스를 끄세요.",
    },
  }),
  exposedEnvFile: rule({
    id: "PG-WEB-012",
    title: "A .env file is served over HTTP",
    category: "secret_exposure",
    severity: "high",
    status: "confirmed",
    confidence: "high",
    standards: { owasp: [MISCONFIGURATION], cwe: ["CWE-538"], cert: [] },
    rationale: {
      en: "Configuration secrets in .env can be downloaded by anyone who can reach the service.",
      ko: ".env에 든 설정 비밀을 서비스에 접근할 수 있는 누구나 내려받을 수 있습니다.",
    },
    remediation: {
      en: "Stop serving dotfiles, move .env out of the web root, and rotate any exposed secrets.",
      ko: "dotfile 제공을 중단하고, .env를 웹 루트 밖으로 옮기고, 노출된 비밀을 교체(rotate)하세요.",
    },
  }),
  exposedGitDirectory: rule({
    id: "PG-WEB-013",
    title: "The .git directory is served over HTTP",
    category: "secret_exposure",
    severity: "high",
    status: "confirmed",
    confidence: "high",
    standards: { owasp: [MISCONFIGURATION], cwe: ["CWE-538"], cert: [] },
    rationale: {
      en: "Source code and history (including past secrets) can be reconstructed from the .git directory.",
      ko: ".git 디렉터리에서 소스 코드와 이력(과거의 비밀 포함)을 복원할 수 있습니다.",
    },
    remediation: {
      en: "Block access to /.git in the web server and keep the repository out of the web root.",
      ko: "웹 서버에서 /.git 접근을 막고 저장소를 웹 루트 밖에 두세요.",
    },
  }),
} as const satisfies Record<string, WebRule>;

export const WEB_RULE_LIST: readonly WebRule[] = Object.values(WEB_RULES);
export const WEB_RULE_IDS: readonly string[] = WEB_RULE_LIST.map((entry) => entry.id);
