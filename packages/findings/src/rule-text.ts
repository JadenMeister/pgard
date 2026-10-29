import type { Finding } from "./contract.js";
import { buildRuleDetails, type RuleDetails } from "./rule-details.js";
import { pickText, type RuleLocale, type RuleMetadata } from "./rule-metadata.js";

/** Korean rule titles. English titles live on the rule definitions (they feed findings). */
export const RULE_TITLES_KO: Readonly<Record<string, string>> = {
  "PG-SECRET-001": "Git에 커밋된 환경 파일",
  "PG-SECRET-002": "추적되는 파일 안의 비밀정보",
  "PG-SECRET-003": "Git 이력에서 발견된 비밀정보",
  "PG-HYGIENE-001": "Git에 커밋된 의존성 디렉터리",
  "PG-DEP-001": "알려진 취약점 권고의 영향 범위에 있는 의존성 버전",
  "PG-SQL-001": "pg/mysql2 쿼리에 동적 문자열로 만든 SQL",
  "PG-SQL-002": "동적 SQL을 쓰는 Prisma unsafe raw 쿼리",
  "PG-SQL-003": "fmt.Sprintf나 문자열 연결로 만든 Go database/sql 쿼리",
  "PG-SQL-004": "fmt.Sprintf나 문자열 연결로 만든 GORM raw SQL 또는 조건",
  "PG-SQL-005": "Java/Kotlin JDBC, JPA/Hibernate, MyBatis 코드에서 동적 문자열로 만든 SQL",
  "PG-SQL-007": "PHP(mysqli, PDO, Laravel, Doctrine)에서 동적 문자열로 만든 SQL",
  "PG-SQL-006": "Python DB-API, SQLAlchemy text(), Django raw SQL에서 동적 문자열로 만든 SQL",
  "PG-XSS-001": "innerHTML/outerHTML/document.write에 쓰는 동적 HTML",
  "PG-XSS-002": "React dangerouslySetInnerHTML에 전달하는 동적 HTML",
  "PG-XSS-003": "Vue v-html에 바인딩한 동적 HTML",
  "PG-XSS-004":
    "Java/Kotlin에서 HTML 응답에 이스케이프 없이 쓰는 요청 데이터(서블릿 writer, JSP, Thymeleaf th:utext)",
  "PG-SSRF-001": "요청 입력에서 온 URL로 보내는 서버 측 HTTP 요청",
  "PG-SSRF-002": "Java/Kotlin에서 요청 입력으로 만든 URL로 보내는 서버 측 HTTP 요청",
  "PG-CMD-001": "동적 문자열로 만든 셸 명령(child_process)",
  "PG-CMD-002": "셸이나 동적 프로그램을 쓰는 Go exec.Command",
  "PG-CMD-003":
    "Java/Kotlin에서 동적 문자열로 만든 OS 명령(Runtime.exec, ProcessBuilder, Commons Exec)",
  "PG-CMD-005":
    "PHP에서 동적 문자열로 만든 OS 명령(exec, system, shell_exec, 백틱, Symfony Process)",
  "PG-CMD-004": "Python에서 동적 문자열로 만든 OS 명령(os.system, subprocess, os.popen)",
  "PG-PATH-001": "파일 읽기/다운로드에 쓰이는 요청 입력 파일 경로",
  "PG-PATH-002":
    "Java/Kotlin 파일 접근에 쓰이는 요청 입력 또는 압축 파일 항목에서 온 파일 경로(경로 조작, zip slip)",
  "PG-CRYPTO-001": "비밀번호에 쓰인 약한 해시(MD5/SHA-1)",
  "PG-CRYPTO-002": "하드코딩된 암호화 키 또는 서명 비밀정보",
  "PG-CRYPTO-003": "취약하거나 더 이상 권장되지 않는 암호화 알고리즘, 고정 IV, 예측 가능한 난수",
  "PG-AUTH-001": "해시 없이 저장된 비밀번호",
  "PG-COOKIE-001": "HttpOnly/Secure/SameSite가 없는 세션·인증 쿠키",
  "PG-CSRF-001": "CSRF 보호가 보이지 않는 쿠키 인증 상태 변경 라우트",
  "PG-BRUTE-001": "속도 제한이 보이지 않는 로그인 또는 비밀번호 재설정 라우트",
  "PG-CONF-001": "접근 제어를 약화하는 Spring Security·Spring Boot 설정",
  "PG-WEB-001": "Content-Security-Policy 헤더 없음",
  "PG-WEB-002": "클릭재킹 방어 헤더 없음",
  "PG-WEB-003": "X-Content-Type-Options: nosniff 없음",
  "PG-WEB-004": "Referrer-Policy 헤더 없음",
  "PG-WEB-005": "HttpOnly 없이 설정된 쿠키",
  "PG-WEB-006": "SameSite 없이 설정된 쿠키",
  "PG-WEB-007": "Secure 없이 설정된 쿠키",
  "PG-WEB-008": "자격 증명과 함께 모든 출처를 허용하는 CORS",
  "PG-WEB-009": "자격 증명과 함께 임의의 Origin을 반사하거나 `null`을 신뢰하는 CORS",
  "PG-WEB-010": "서버 소프트웨어 버전 노출",
  "PG-WEB-011": "디렉터리 목록 활성화",
  "PG-WEB-012": "HTTP로 제공되는 .env 파일",
  "PG-WEB-013": "HTTP로 제공되는 .git 디렉터리",
};

/** One set of finding texts in each language. */
export interface FindingTextVariant {
  title: Record<RuleLocale, string>;
  impact: Record<RuleLocale, string>;
  recommendation: Record<RuleLocale, string>;
}

/**
 * Finding texts of a rule for another source than the rule's own (its definition describes Git
 * history). `working_tree`: a secret found in the files on disk by a code-only scan (JSON 1.7),
 * which may never have been committed, so it never says "tracked" or "committed to Git". The
 * rule id and the finding fingerprint stay the same.
 */
export const FINDING_TEXT_VARIANTS: Readonly<
  Record<string, Readonly<Record<"working_tree", FindingTextVariant>>>
> = {
  "PG-SECRET-001": {
    working_tree: {
      title: {
        en: "Environment file in the project folder",
        ko: "프로젝트 폴더의 환경 파일",
      },
      impact: {
        en: "A `.env` file usually holds API keys, database passwords and signing secrets. Anyone who gets a copy of the folder, through a commit, a shared drive, a build image or an upload, can use them.",
        ko: "`.env` 파일에는 보통 API 키, 데이터베이스 비밀번호, 서명 비밀정보가 들어 있습니다. 커밋, 공유 드라이브, 빌드 이미지, 업로드 등으로 폴더 사본을 얻은 사람은 누구나 이를 사용할 수 있습니다.",
      },
      recommendation: {
        en: "Keep the file out of version control and out of shared copies: add .env to .gitignore and commit a .env.example that lists the variable names without values. If the file was ever committed, pushed or shared, rotate the values at the provider.",
        ko: "이 파일을 버전 관리와 공유 사본에서 빼세요. .env를 .gitignore에 추가하고, 값 없이 변수 이름만 적은 .env.example을 커밋하세요. 파일을 커밋·푸시·공유한 적이 있다면 발급처에서 값을 교체(rotate)하세요.",
      },
    },
  },
  "PG-SECRET-002": {
    working_tree: {
      title: { en: "Secret in a project file", ko: "프로젝트 파일 안의 비밀정보" },
      impact: {
        en: "A credential written in a source or configuration file reaches everyone who gets the file, through a commit, a shared folder, a build artifact or a log, and lets them authenticate as its owner. Automated scanners find keys pushed to public hosts within minutes.",
        ko: "소스나 설정 파일에 적힌 자격 증명은 커밋, 공유 폴더, 빌드 산출물, 로그 등으로 그 파일을 얻은 누구에게나 전달되며, 그 사람은 소유자로 인증할 수 있습니다. 공개 호스트에 올라간 키는 자동 스캐너가 몇 분 안에 찾아냅니다.",
      },
      recommendation: {
        en: "Remove the value from the file and load it from the environment or a secret manager. If the file was ever committed, pushed or shared, treat the value as compromised and revoke or rotate it at the provider first.",
        ko: "파일에서 값을 지우고 환경 변수나 비밀정보 관리 도구(secret manager)에서 불러오세요. 파일을 커밋·푸시·공유한 적이 있다면 값이 유출된 것으로 보고 먼저 발급처에서 폐기하거나 교체(rotate)하세요.",
      },
    },
  },
};

/** What a rule contributes to rendering: its title and the two finding texts, in each language. */
export interface RuleTexts {
  title: Record<RuleLocale, string>;
  impact: Record<RuleLocale, string>;
  recommendation: Record<RuleLocale, string>;
  /** Standards links, examples and the rule-level texts; absent in hand-built catalogs. */
  details?: RuleDetails;
  /** Other finding texts of the rule (`FINDING_TEXT_VARIANTS`), matched by the English title. */
  variants?: FindingTextVariant[];
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
      ...(FINDING_TEXT_VARIANTS[rule.id] === undefined
        ? {}
        : { variants: Object.values(FINDING_TEXT_VARIANTS[rule.id] ?? {}) }),
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
  const rule = catalog.get(finding.ruleId);
  if (rule === undefined) return finding;
  // A finding written with a variant's English texts is translated with that variant.
  const texts: FindingTextVariant =
    rule.variants?.find((variant) => variant.title.en === finding.title) ?? rule;
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
