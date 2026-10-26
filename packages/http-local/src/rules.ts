import {
  copyRuleMetadata,
  type Confidence,
  type FindingCategory,
  type FindingReferences,
  type FindingStatus,
  type RuleMetadata,
  type Severity,
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

function rule(definition: WebRuleDefinition): WebRule {
  const { standards, rationale, remediation, examples, ...identity } = definition;
  const metadata = copyRuleMetadata({
    standards,
    rationale,
    remediation,
    ...(examples === undefined ? {} : { examples }),
  });
  return {
    ...identity,
    impact: metadata.rationale.en,
    recommendation: metadata.remediation.en,
    references: {
      cwe: [...metadata.standards.cwe],
      owasp: [...metadata.standards.owasp],
      cve: [],
    },
    metadata,
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
    standards: {
      owasp: ["A06:2025"],
      cwe: ["CWE-693"],
      cert: [],
      mappingNote: {
        discouragedCwe: {
          en: "CWE-693 is a Pillar that MITRE marks DISCOURAGED for mapping. No specific CWE describes a missing Content-Security-Policy header, so it is kept and its OWASP category (A06) follows the OWASP mapped-CWE list.",
          ko: "CWE-693은 MITRE가 매핑에 쓰지 말라고(DISCOURAGED) 표시한 Pillar입니다. Content-Security-Policy 헤더 누락을 정확히 설명하는 CWE가 없어 유지하며, OWASP 범주(A06)는 OWASP 매핑 CWE 목록을 따릅니다.",
        },
      },
    },
    rationale: {
      en: "A Content-Security-Policy limits where scripts may load from and run. Without one, an XSS flaw elsewhere can run injected script freely and send data out; with one, many of those attacks are blocked. The missing header alone is not a vulnerability.",
      ko: "Content-Security-Policy는 스크립트를 어디서 불러오고 실행할 수 있는지 제한합니다. 없으면 다른 곳의 XSS 결함으로 주입된 스크립트가 자유롭게 실행되어 데이터를 내보낼 수 있고, 있으면 그런 공격 상당수를 막을 수 있습니다. 헤더가 없다는 사실만으로는 취약점이 아닙니다.",
    },
    remediation: {
      en: "Send a policy on HTML responses, starting strict: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'`. Avoid `'unsafe-inline'` (use nonces or hashes for inline scripts), and try the policy with `Content-Security-Policy-Report-Only` first.",
      ko: "HTML 응답에 엄격한 정책으로 시작해 설정하세요: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'`. `'unsafe-inline'`은 피하고(인라인 스크립트에는 nonce나 해시 사용), 먼저 `Content-Security-Policy-Report-Only`로 시험해 보세요.",
    },
  }),
  missingFrameProtection: rule({
    id: "PG-WEB-002",
    title: "Clickjacking protection header is missing",
    category: "misconfiguration",
    severity: "low",
    status: "informational",
    confidence: "high",
    standards: { owasp: ["A06:2025"], cwe: ["CWE-1021"], cert: [] },
    rationale: {
      en: "If another site can load the page in a frame, an attacker can overlay it invisibly and trick a logged-in user into clicking its buttons (clickjacking), for example to change settings or confirm a payment.",
      ko: "다른 사이트가 이 페이지를 프레임으로 불러올 수 있으면, 공격자가 페이지를 투명하게 덮어 로그인한 사용자가 그 버튼을 누르도록 속일 수 있습니다(클릭재킹). 예를 들어 설정을 바꾸거나 결제를 확정하게 만들 수 있습니다.",
    },
    remediation: {
      en: "Send `Content-Security-Policy: frame-ancestors 'none'` (or `'self'` if you frame your own pages), plus `X-Frame-Options: DENY` or `SAMEORIGIN` for old browsers. If a page must be embeddable, list the allowed origins explicitly in `frame-ancestors`.",
      ko: "`Content-Security-Policy: frame-ancestors 'none'`(자기 페이지를 프레임으로 쓴다면 `'self'`)을 설정하고, 오래된 브라우저를 위해 `X-Frame-Options: DENY` 또는 `SAMEORIGIN`도 설정하세요. 페이지를 임베드할 수 있어야 한다면 허용할 origin을 `frame-ancestors`에 명시하세요.",
    },
  }),
  missingNoSniff: rule({
    id: "PG-WEB-003",
    title: "X-Content-Type-Options: nosniff is missing",
    category: "misconfiguration",
    severity: "info",
    status: "informational",
    confidence: "high",
    standards: {
      owasp: ["A06:2025"],
      cwe: ["CWE-693"],
      cert: [],
      mappingNote: {
        discouragedCwe: {
          en: "CWE-693 is a Pillar that MITRE marks DISCOURAGED for mapping. No specific CWE describes a missing X-Content-Type-Options header, so it is kept and its OWASP category (A06) follows the OWASP mapped-CWE list.",
          ko: "CWE-693은 MITRE가 매핑에 쓰지 말라고(DISCOURAGED) 표시한 Pillar입니다. X-Content-Type-Options 헤더 누락을 정확히 설명하는 CWE가 없어 유지하며, OWASP 범주(A06)는 OWASP 매핑 CWE 목록을 따릅니다.",
        },
      },
    },
    rationale: {
      en: "Without `nosniff`, some browsers guess a response's type from its content. A file served as text or an image, such as an upload, that contains script may then be run as JavaScript or HTML.",
      ko: "`nosniff`가 없으면 일부 브라우저가 응답의 내용을 보고 타입을 추측합니다. 업로드된 파일처럼 텍스트나 이미지로 제공한 파일에 스크립트가 들어 있으면 JavaScript나 HTML로 실행될 수 있습니다.",
    },
    remediation: {
      en: "Send `X-Content-Type-Options: nosniff` on all responses, and set an accurate `Content-Type` on every response, including uploaded files.",
      ko: "모든 응답에 `X-Content-Type-Options: nosniff`를 설정하고, 업로드된 파일을 포함한 모든 응답에 정확한 `Content-Type`을 지정하세요.",
    },
  }),
  missingReferrerPolicy: rule({
    id: "PG-WEB-004",
    title: "Referrer-Policy header is missing",
    category: "misconfiguration",
    severity: "info",
    status: "informational",
    confidence: "high",
    standards: { owasp: ["A01:2025"], cwe: ["CWE-201"], cert: [] },
    rationale: {
      en: "When a user follows a link or loads a resource from another site, the browser may send the full URL in the `Referer` header. If URLs carry ids, search terms or tokens (a password-reset link, for example), the other site, its analytics and its logs receive them.",
      ko: "사용자가 링크를 따라가거나 다른 사이트의 리소스를 불러올 때 브라우저가 `Referer` 헤더에 전체 URL을 보낼 수 있습니다. URL에 id, 검색어, 토큰(예: 비밀번호 재설정 링크)이 들어 있으면 상대 사이트와 그 분석 도구·로그가 이를 받게 됩니다.",
    },
    remediation: {
      en: "Send `Referrer-Policy: strict-origin-when-cross-origin` (also the default in current browsers, so setting it mainly makes the policy explicit and covers older browsers), or `no-referrer` on pages whose URLs are sensitive. Do not put secrets or tokens in URLs.",
      ko: "`Referrer-Policy: strict-origin-when-cross-origin`을 설정하세요(최신 브라우저의 기본값이기도 하므로, 명시해 두면 정책이 분명해지고 오래된 브라우저도 보호됩니다). URL이 민감한 페이지에는 `no-referrer`를 쓰세요. URL에 비밀정보나 토큰을 넣지 마세요.",
    },
  }),
  cookieWithoutHttpOnly: rule({
    id: "PG-WEB-005",
    title: "Cookie is set without HttpOnly",
    category: "misconfiguration",
    severity: "low",
    status: "suspected",
    confidence: "medium",
    standards: { owasp: ["A02:2025"], cwe: ["CWE-1004"], cert: [] },
    rationale: {
      en: "A cookie that JavaScript can read is stolen by any injected script (`document.cookie`), so an XSS flaw becomes a session takeover if the cookie holds the session. PGARD reports this as suspected because it cannot tell whether this cookie carries a session.",
      ko: "JavaScript가 읽을 수 있는 쿠키는 주입된 스크립트가 훔칠 수 있으므로(`document.cookie`), 쿠키가 세션을 담고 있다면 XSS 결함이 세션 탈취로 이어집니다. 이 쿠키가 세션을 담는지 PGARD가 알 수 없으므로 의심 항목으로 보고합니다.",
    },
    remediation: {
      en: "Add the `HttpOnly` attribute to session and authentication cookies, together with `Secure` and `SameSite=Lax`. Cookies the front end must read can stay without it, but must not hold secrets.",
      ko: "세션·인증 쿠키에 `HttpOnly` 속성을 `Secure`, `SameSite=Lax`와 함께 설정하세요. 프런트엔드가 읽어야 하는 쿠키는 없이 둘 수 있지만 비밀정보를 담아서는 안 됩니다.",
    },
  }),
  cookieWithoutSameSite: rule({
    id: "PG-WEB-006",
    title: "Cookie is set without SameSite",
    category: "csrf",
    severity: "low",
    status: "suspected",
    confidence: "medium",
    standards: { owasp: ["A01:2025"], cwe: ["CWE-1275"], cert: [] },
    rationale: {
      en: "Without SameSite, the browser applies its own default, and some browsers attach the cookie to requests started by other sites. That enables CSRF against a logged-in user and lets cross-site embeds use the login state.",
      ko: "SameSite가 없으면 브라우저가 자체 기본값을 적용하며, 일부 브라우저는 다른 사이트가 시작한 요청에도 쿠키를 실습니다. 그러면 로그인한 사용자에 대한 CSRF가 가능해지고, 다른 사이트의 임베드가 로그인 상태를 이용할 수 있습니다.",
    },
    remediation: {
      en: "Set `SameSite=Lax` on session cookies, or `Strict` if no cross-site entry is needed. `SameSite=None` requires `Secure` and is only for cookies that really must be sent cross-site.",
      ko: "세션 쿠키에 `SameSite=Lax`를 설정하고, 다른 사이트에서 들어올 일이 없다면 `Strict`를 쓰세요. `SameSite=None`은 `Secure`가 필요하며 정말 다른 사이트로 보내야 하는 쿠키에만 쓰세요.",
    },
  }),
  cookieWithoutSecure: rule({
    id: "PG-WEB-007",
    title: "Cookie is set without Secure",
    category: "misconfiguration",
    severity: "info",
    status: "informational",
    confidence: "medium",
    standards: { owasp: ["A02:2025"], cwe: ["CWE-614"], cert: [] },
    rationale: {
      en: "A cookie without Secure is also sent over plain HTTP, so anyone on the network path (public Wi-Fi, for instance) can read or replace it. On a plain-http loopback server this is expected; the check matters for the HTTPS deployment.",
      ko: "Secure가 없는 쿠키는 평문 HTTP로도 전송되므로, 네트워크 경로상의 누구나(예: 공용 Wi-Fi) 쿠키를 읽거나 바꿀 수 있습니다. 평문 HTTP loopback 서버에서는 예상되는 결과이며, 이 검사는 HTTPS 배포 환경에서 의미가 있습니다.",
    },
    remediation: {
      en: "Set `Secure` on all cookies in HTTPS deployments and send `Strict-Transport-Security` so browsers never fall back to HTTP. Chrome and Firefox accept Secure cookies on `http://localhost`, so local development can keep it on; on other plain-http hosts the cookie is not stored, so make it depend on the environment there.",
      ko: "HTTPS 배포에서는 모든 쿠키에 `Secure`를 설정하고 `Strict-Transport-Security`를 보내 브라우저가 HTTP로 되돌아가지 않게 하세요. Chrome, Firefox는 `http://localhost`에서 Secure 쿠키를 받아들이므로 로컬 개발에서는 켜 둘 수 있고, 그 밖의 평문 http 호스트에서는 쿠키가 저장되지 않으므로 환경에 따라 켜고 끄도록 하세요.",
    },
  }),
  corsWildcardWithCredentials: rule({
    id: "PG-WEB-008",
    title: "CORS allows any origin together with credentials",
    category: "misconfiguration",
    severity: "medium",
    status: "suspected",
    confidence: "medium",
    standards: { owasp: ["A02:2025"], cwe: ["CWE-942"], cert: [] },
    rationale: {
      en: "Allowing any origin while credentials are enabled points to a misconfigured CORS policy. Browsers refuse the literal `*` with credentials, so the real risk is a server that works around it by echoing the request's Origin (see PG-WEB-009), after which any website can read authenticated responses.",
      ko: "자격 증명을 켠 채 모든 origin을 허용하는 것은 CORS 설정이 잘못되었다는 신호입니다. 브라우저는 자격 증명과 함께 쓰인 `*`를 거부하므로, 실제 위험은 서버가 요청의 Origin을 그대로 반영해 이를 우회하는 경우입니다(PG-WEB-009 참고). 그러면 어떤 웹사이트든 인증된 응답을 읽을 수 있습니다.",
    },
    remediation: {
      en: "When credentials are enabled, set `Access-Control-Allow-Origin` to one specific trusted origin (picked from an allowlist), never `*`, and add `Vary: Origin` when the value depends on the request. If you do not need cookies cross-origin, drop `Access-Control-Allow-Credentials`.",
      ko: "자격 증명을 켠 경우 `Access-Control-Allow-Origin`은 허용 목록(allowlist)에서 고른 신뢰하는 특정 origin 하나로 설정하고 `*`는 쓰지 마세요. 값이 요청에 따라 달라지면 `Vary: Origin`을 추가하세요. 다른 origin에서 쿠키가 필요 없다면 `Access-Control-Allow-Credentials`를 빼세요.",
    },
  }),
  corsReflectedOrigin: rule({
    id: "PG-WEB-009",
    title: "CORS reflects an arbitrary Origin with credentials",
    category: "access_control",
    severity: "high",
    status: "suspected",
    confidence: "medium",
    standards: { owasp: ["A02:2025"], cwe: ["CWE-942"], cert: [] },
    rationale: {
      en: "The server echoes whatever Origin the request sends and allows credentials. A page on any website the logged-in user visits can then call this service with `fetch()` using the user's cookies and read the response: profile data, tokens, anything that user can see.",
      ko: "서버가 요청이 보낸 Origin을 그대로 돌려주면서 자격 증명을 허용합니다. 그러면 로그인한 사용자가 방문한 아무 웹사이트의 페이지가 사용자의 쿠키로 이 서비스를 `fetch()`로 호출해 프로필 정보, 토큰 등 그 사용자가 볼 수 있는 모든 응답을 읽을 수 있습니다.",
    },
    remediation: {
      en: "Compare `Origin` with an exact allowlist and reply only with a matching value (plus `Vary: Origin`); otherwise send no CORS headers. Never reflect the header, never allow `null`, and avoid substring or regex checks that also match hosts like `evil-example.com`.",
      ko: "`Origin`을 정확히 일치하는 허용 목록(allowlist)과 대조해 일치하는 값만 응답하고(`Vary: Origin` 포함), 그렇지 않으면 CORS 헤더를 보내지 마세요. 헤더를 그대로 반영하지 말고, `null`을 허용하지 말며, `evil-example.com` 같은 호스트까지 일치시키는 부분 문자열·정규식 검사는 피하세요.",
    },
  }),
  versionDisclosure: rule({
    id: "PG-WEB-010",
    title: "Server software version is disclosed",
    category: "misconfiguration",
    severity: "low",
    status: "confirmed",
    confidence: "high",
    standards: { owasp: ["A01:2025"], cwe: ["CWE-497"], cert: [] },
    rationale: {
      en: "A header such as `Server: nginx/1.18.0` or `X-Powered-By: Express` tells attackers which software and version to look up known exploits for, so they can skip guessing. It does not create a flaw by itself; running outdated software does.",
      ko: "`Server: nginx/1.18.0`이나 `X-Powered-By: Express` 같은 헤더는 공격자에게 어떤 소프트웨어와 버전의 알려진 익스플로잇을 찾아볼지 알려 주어 추측 과정을 건너뛰게 합니다. 이것만으로 결함이 생기는 것은 아니며, 결함은 오래된 소프트웨어를 쓰는 데서 생깁니다.",
    },
    remediation: {
      en: "Remove or genericize the headers: `server_tokens off;` (nginx), `ServerTokens Prod` (Apache), `app.disable('x-powered-by')` or `helmet()` (Express). Hiding the version is minor hardening; the real fix is to keep the software patched.",
      ko: "헤더를 제거하거나 일반화하세요: `server_tokens off;`(nginx), `ServerTokens Prod`(Apache), `app.disable('x-powered-by')` 또는 `helmet()`(Express). 버전을 숨기는 것은 가벼운 보강일 뿐이며, 근본적인 해결은 소프트웨어를 최신으로 패치하는 것입니다.",
    },
  }),
  directoryListing: rule({
    id: "PG-WEB-011",
    title: "Directory listing is enabled",
    category: "misconfiguration",
    severity: "medium",
    status: "confirmed",
    confidence: "high",
    standards: { owasp: ["A01:2025"], cwe: ["CWE-548"], cert: [] },
    rationale: {
      en: "With automatic directory indexes, anyone can browse a folder and download files that were never linked from the site, such as backups, exports, source maps and configuration.",
      ko: "자동 디렉터리 인덱스가 켜져 있으면 누구나 폴더를 둘러보고, 사이트에서 링크한 적 없는 백업, 내보내기 파일, 소스 맵, 설정 파일까지 내려받을 수 있습니다.",
    },
    remediation: {
      en: "Disable indexes (`autoindex off;` in nginx, `Options -Indexes` in Apache, no `serve-index` middleware in Express), serve only a dedicated public folder, and remove stray files from it.",
      ko: "인덱스를 끄세요(nginx는 `autoindex off;`, Apache는 `Options -Indexes`, Express는 `serve-index` 미들웨어를 쓰지 않기). 전용 공개 폴더만 제공하고 그 안의 불필요한 파일은 지우세요.",
    },
  }),
  exposedEnvFile: rule({
    id: "PG-WEB-012",
    title: "A .env file is served over HTTP",
    category: "secret_exposure",
    severity: "high",
    status: "confirmed",
    confidence: "high",
    standards: { owasp: ["A01:2025"], cwe: ["CWE-538"], cert: [] },
    rationale: {
      en: "A reachable `/.env` returns database passwords, API keys and signing secrets to anyone who requests it, and attackers scan for this path automatically. Treat every value in it as already exposed.",
      ko: "접근 가능한 `/.env`는 요청하는 누구에게나 데이터베이스 비밀번호, API 키, 서명 비밀정보을 돌려주며, 공격자는 이 경로를 자동으로 스캔합니다. 그 안의 모든 값이 이미 노출된 것으로 간주하세요.",
    },
    remediation: {
      en: "Serve static files from a dedicated public directory that does not contain `.env`, deny dotfiles in the server configuration (`location ~ /\\.(?!well-known) { deny all; }` in nginx), and rotate every secret that was in the file, because it was readable.",
      ko: "`.env`가 없는 전용 공개 디렉터리에서만 정적 파일을 제공하고, 서버 설정에서 점(.)으로 시작하는 파일(dotfile)을 거부하세요(nginx는 `location ~ /\\.(?!well-known) { deny all; }`, `.well-known`은 예외). 파일에 있던 모든 비밀정보는 읽을 수 있었으므로 교체(rotate)하세요.",
    },
  }),
  exposedGitDirectory: rule({
    id: "PG-WEB-013",
    title: "The .git directory is served over HTTP",
    category: "secret_exposure",
    severity: "high",
    status: "confirmed",
    confidence: "high",
    standards: { owasp: ["A01:2025"], cwe: ["CWE-527", "CWE-538"], cert: [] },
    rationale: {
      en: "A reachable `/.git/` lets an attacker download the repository objects and rebuild the full source and history with tools such as git-dumper, including secrets that were committed and later deleted.",
      ko: "접근 가능한 `/.git/`이 있으면 공격자가 저장소 객체를 내려받아 git-dumper 같은 도구로 전체 소스와 이력을 복원할 수 있습니다. 커밋했다가 나중에 지운 비밀정보도 포함됩니다.",
    },
    remediation: {
      en: "Block `/.git` in the web server (`location ~ /\\.git { deny all; }` in nginx), deploy build output instead of a repository checkout, and rotate any secret that appears in the history.",
      ko: "웹 서버에서 `/.git` 접근을 막고(nginx는 `location ~ /\\.git { deny all; }`), 저장소를 체크아웃한 상태가 아니라 빌드 산출물을 배포하며, 이력에 나타나는 비밀정보는 교체(rotate)하세요.",
    },
  }),
} as const satisfies Record<string, WebRule>;

export const WEB_RULE_LIST: readonly WebRule[] = Object.values(WEB_RULES);
export const WEB_RULE_IDS: readonly string[] = WEB_RULE_LIST.map((entry) => entry.id);
