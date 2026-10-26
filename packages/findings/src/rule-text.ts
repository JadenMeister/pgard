import type { Finding } from "./contract.js";
import { buildRuleDetails, type RuleDetails } from "./rule-details.js";
import { pickText, type RuleLocale, type RuleMetadata } from "./rule-metadata.js";

/** Korean rule titles. English titles live on the rule definitions (they feed findings). */
export const RULE_TITLES_KO: Readonly<Record<string, string>> = {
  "PG-SECRET-001": "Git에 커밋된 환경 파일",
  "PG-SECRET-002": "추적되는 파일 안의 비밀정보",
  "PG-SECRET-003": "Git 이력에서 발견된 비밀정보",
  "PG-HYGIENE-001": "Git에 커밋된 의존성 디렉터리",
  "PG-SQL-001": "pg/mysql2 쿼리에 동적 문자열로 만든 SQL",
  "PG-SQL-002": "동적 SQL을 쓰는 Prisma unsafe raw 쿼리",
  "PG-SQL-003": "fmt.Sprintf나 문자열 연결로 만든 Go database/sql 쿼리",
  "PG-SQL-004": "fmt.Sprintf나 문자열 연결로 만든 GORM raw SQL 또는 조건",
  "PG-XSS-001": "innerHTML/outerHTML/document.write에 쓰는 동적 HTML",
  "PG-XSS-002": "React dangerouslySetInnerHTML에 전달하는 동적 HTML",
  "PG-XSS-003": "Vue v-html에 바인딩한 동적 HTML",
  "PG-SSRF-001": "요청 입력에서 온 URL로 보내는 서버 측 HTTP 요청",
  "PG-CMD-001": "동적 문자열로 만든 셸 명령(child_process)",
  "PG-CMD-002": "셸이나 동적 프로그램을 쓰는 Go exec.Command",
  "PG-PATH-001": "파일 읽기/다운로드에 쓰이는 요청 입력 파일 경로",
  "PG-CRYPTO-001": "비밀번호에 쓰인 약한 해시(MD5/SHA-1)",
  "PG-CRYPTO-002": "하드코딩된 암호화 키 또는 서명 비밀정보",
  "PG-CRYPTO-003": "취약하거나 더 이상 권장되지 않는 암호화 알고리즘",
  "PG-AUTH-001": "해시 없이 저장된 비밀번호",
  "PG-COOKIE-001": "HttpOnly/Secure/SameSite가 없는 세션·인증 쿠키",
  "PG-CSRF-001": "CSRF 보호가 보이지 않는 쿠키 인증 상태 변경 라우트",
  "PG-BRUTE-001": "속도 제한이 보이지 않는 로그인 또는 비밀번호 재설정 라우트",
  "PG-WEB-001": "Content-Security-Policy 헤더 없음",
  "PG-WEB-002": "클릭재킹 방어 헤더 없음",
  "PG-WEB-003": "X-Content-Type-Options: nosniff 없음",
  "PG-WEB-004": "Referrer-Policy 헤더 없음",
  "PG-WEB-005": "HttpOnly 없이 설정된 쿠키",
  "PG-WEB-006": "SameSite 없이 설정된 쿠키",
  "PG-WEB-007": "Secure 없이 설정된 쿠키",
  "PG-WEB-008": "자격 증명과 함께 모든 출처를 허용하는 CORS",
  "PG-WEB-009": "자격 증명과 함께 임의의 Origin을 그대로 반사하는 CORS",
  "PG-WEB-010": "서버 소프트웨어 버전 노출",
  "PG-WEB-011": "디렉터리 목록 활성화",
  "PG-WEB-012": "HTTP로 제공되는 .env 파일",
  "PG-WEB-013": "HTTP로 제공되는 .git 디렉터리",
};

/** What a rule contributes to rendering: its title and the two finding texts, in each language. */
export interface RuleTexts {
  title: Record<RuleLocale, string>;
  impact: Record<RuleLocale, string>;
  recommendation: Record<RuleLocale, string>;
  /** Standards links, examples and the rule-level texts; absent in hand-built catalogs. */
  details?: RuleDetails;
}

export type RuleTextCatalog = ReadonlyMap<string, RuleTexts>;

/** Builds the catalog from any rule list (code, history and web rules share this shape). */
export function buildRuleTextCatalog(
  rules: Iterable<{ id: string; title: string; metadata: RuleMetadata }>,
): RuleTextCatalog {
  const catalog = new Map<string, RuleTexts>();
  for (const rule of rules) {
    catalog.set(rule.id, {
      title: { en: rule.title, ko: RULE_TITLES_KO[rule.id] ?? rule.title },
      impact: rule.metadata.rationale,
      recommendation: rule.metadata.remediation,
      details: buildRuleDetails(rule.metadata),
    });
  }
  return catalog;
}

/** The translated title of a rule, or `fallback` when the rule is unknown. */
export function localizedRuleTitle(
  catalog: RuleTextCatalog,
  ruleId: string,
  locale: RuleLocale,
  fallback: string,
): string {
  const texts = catalog.get(ruleId);
  return texts === undefined ? fallback : pickText(texts.title, locale);
}

/**
 * Returns the finding with its title, impact and recommendation in `locale`. A field is replaced
 * only when it still equals the rule's English default; a finding that carries its own text (for
 * example a recommendation written for one situation) keeps that text, so a translated default
 * never contradicts it. The JSON result is not touched: call this at render time only.
 */
export function localizeFinding<T extends Finding>(
  finding: T,
  catalog: RuleTextCatalog,
  locale: RuleLocale,
): T {
  if (locale === "en") return finding;
  const texts = catalog.get(finding.ruleId);
  if (texts === undefined) return finding;
  return {
    ...finding,
    title: finding.title === texts.title.en ? texts.title[locale] : finding.title,
    impact: finding.impact === texts.impact.en ? texts.impact[locale] : finding.impact,
    recommendation:
      finding.recommendation === texts.recommendation.en
        ? texts.recommendation[locale]
        : finding.recommendation,
  };
}

export function localizeFindings<T extends Finding>(
  findings: readonly T[],
  catalog: RuleTextCatalog,
  locale: RuleLocale,
): T[] {
  return locale === "en" ? [...findings] : findings.map((f) => localizeFinding(f, catalog, locale));
}
