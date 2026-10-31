/**
 * Coverage notes with a structured code (result schema 1.8).
 *
 * A coverage note is English text written by an analyzer. From 1.8 an analyzer may also record
 * `noteCode` and `noteParams` next to that text, so a frontend can show it in another language.
 * The English text stays exactly as before (it is built from this catalog's English template, so
 * the two cannot drift), which keeps stored results, baselines and comparisons unchanged.
 *
 * A reader never trusts the code blindly: the Korean text comes from this catalog only when the
 * code is known AND its params pass validation (the expected keys, integers in range, short
 * plain labels, hexadecimal ids or one of a fixed list of words). Anything else, including every
 * result written before 1.8, falls back to the stored text. A param can therefore never carry
 * markup or a long free-text string into the output, and every frontend still escapes its output.
 */

export type NoteLanguage = "en" | "ko";
export type NoteParamValue = string | number;
export type NoteParams = Record<string, NoteParamValue>;

/** The structured part of a coverage entry (both fields are optional and travel together). */
export interface CoverageNoteCode {
  noteCode?: string;
  noteParams?: NoteParams;
}

/**
 * - `count`: a safe integer from 0 to 1 000 000 000.
 * - `label`: 1 to 60 characters of letters, digits, space and `. _ + # ( ) / : -`, starting with
 *   a letter or digit (a language, library or ecosystem name, a date, a revision as typed).
 * - `hex`: 1 to 64 lowercase hexadecimal characters (a commit prefix or a set fingerprint).
 * - a list: exactly one of the listed words.
 */
type ParamKind = "count" | "label" | "hex" | readonly string[];
type ParamSpec = ParamKind | { kind: ParamKind; optional: true };

const MAX_COUNT = 1_000_000_000;
const LABEL = /^[A-Za-z0-9][A-Za-z0-9 ._+#()/:-]{0,59}$/;
const HEX = /^[0-9a-f]{1,64}$/;

/** Set on a note that an early-stopped directory walk prefixed; see `WALK_STOPPED_PREFIX`. */
const WALK_STOPPED_PARAM = "walkStopped";

type Values<S extends Record<string, ParamSpec>> = { [K in keyof S]: NoteParamValue };

interface CatalogEntry {
  params: Record<string, ParamSpec>;
  en: (p: Record<string, NoteParamValue>) => string;
  ko: (p: Record<string, NoteParamValue>) => string;
}

function entry<S extends Record<string, ParamSpec>>(
  params: S,
  en: (p: Values<S>) => string,
  ko: (p: Values<S>) => string,
): CatalogEntry {
  return { params, en, ko } as unknown as CatalogEntry;
}

const none = {} as const;
const plural = (count: NoteParamValue, one: string, many: string): string =>
  count === 1 ? one : many;

/** Method texts of the JavaScript, TypeScript, Vue and Go areas (English, as stored). */
const LANGUAGE_METHODS = {
  js: "TypeScript compiler AST with intra-file, flow-insensitive taint tracking",
  vue: "script blocks via TypeScript AST, template v-html via @vue/compiler-sfc",
  go: "syntax-level heuristics (lexer and patterns, no type information or cross-file data flow)",
} as const;
const LANGUAGE_METHODS_KO = {
  js: "TypeScript 컴파일러 AST와 파일 안의 흐름 비민감 오염 추적",
  vue: "스크립트 블록은 TypeScript AST, 템플릿 v-html은 @vue/compiler-sfc",
  go: "구문 수준 휴리스틱(렉서와 패턴, 타입 정보와 파일 간 데이터 흐름 없음)",
} as const;
/** The English method text of a language area, as stored in its coverage note. */
export const languageMethodText = (key: "js" | "vue" | "go"): string => LANGUAGE_METHODS[key];
const METHOD_KEYS = Object.keys(LANGUAGE_METHODS);
const methodEn = (key: NoteParamValue): string =>
  LANGUAGE_METHODS[key as keyof typeof LANGUAGE_METHODS];
const methodKo = (key: NoteParamValue): string =>
  LANGUAGE_METHODS_KO[key as keyof typeof LANGUAGE_METHODS_KO];

/** The English update hint of the dependency check (the same text the producer stores). */
const UPDATE_HINT_EN = "Run `pgard advisories update` to download the OSV data.";
const UPDATE_HINT_KO = "`pgard advisories update`를 실행해 OSV 데이터를 내려받으세요.";

/** English line that leads every note of an area the directory walk left incomplete. */
export const WALK_STOPPED_PREFIX =
  "The directory walk stopped early (see source:walk); files beyond that point were not found.";

/**
 * Every code a producer may emit, with its English and Korean text. Add a code here before using
 * it in an analyzer; the catalog test fails when a code lacks either language or a producer emits
 * one that is not listed.
 */
export const COVERAGE_NOTE_CATALOG: Readonly<Record<string, CatalogEntry>> = {
  // scan-core
  no_coverage: entry(
    none,
    () => "No coverage reported.",
    () => "보고된 검사 범위가 없습니다.",
  ),
  authorization_incomplete: entry(
    none,
    () => "Authorization could not be completed.",
    () => "권한 확인을 끝내지 못했습니다.",
  ),
  blocked_by_gate: entry(
    none,
    () => "Blocked by the authorization gate.",
    () => "권한 확인에서 차단되었습니다.",
  ),
  web_target_missing: entry(
    none,
    () => "No confirmed local web target was selected.",
    () => "확인된 로컬 웹 대상이 선택되지 않았습니다.",
  ),
  web_scanner_unavailable: entry(
    none,
    () => "The web scanner is not available.",
    () => "웹 검사기를 사용할 수 없습니다.",
  ),
  analyzer_failed: entry(
    { scope: ["code", "history", "web"] },
    (p) => `The ${p.scope} analyzer failed; results for this area are missing.`,
    (p) =>
      `${p.scope === "code" ? "코드" : p.scope === "history" ? "Git 기록" : "웹"} 분석기가 실패해 이 영역의 결과가 없습니다.`,
  ),
  dependency_check_failed: entry(
    none,
    () =>
      "The dependency check failed unexpectedly; no lockfile was checked for known vulnerable versions.",
    () =>
      "의존성 검사가 예기치 않게 실패해 알려진 취약 버전을 어떤 lockfile에서도 확인하지 못했습니다.",
  ),
  history_config_excluded: entry(
    { patterns: "count", set: "hex" },
    (p) =>
      `0 files excluded from history by pgard.config.json: its ${p.patterns} exclude pattern${plural(p.patterns, "", "s")} (set ${p.set}) do not apply to Git history or to tracked files, which are always scanned in full.`,
    (p) =>
      `pgard.config.json으로 Git 기록에서 제외된 파일 0개: exclude 패턴 ${p.patterns}개(집합 ${p.set})는 Git 기록과 추적 파일에 적용되지 않으며, 이들은 항상 전부 검사합니다.`,
  ),
  working_tree_files_checked: entry(
    { count: "count" },
    (p) => `${p.count} file(s) on disk checked for secrets.`,
    (p) => `디스크의 파일 ${p.count}개에서 비밀값을 확인했습니다.`,
  ),

  // source-analysis
  walk_stopped_early: entry(
    none,
    () => WALK_STOPPED_PREFIX,
    () => "디렉터리 탐색이 일찍 멈췄습니다(source:walk 참고). 그 뒤의 파일은 찾지 못했습니다.",
  ),
  walk_stopped_entries: entry(
    { visited: "count", limit: "count" },
    (p) =>
      `The directory walk stopped after ${p.visited} entries (limit ${p.limit}); files beyond that point were not found or analyzed. Exclude generated or junk directories to scan the rest.`,
    (p) =>
      `디렉터리 탐색이 항목 ${p.visited}개에서 멈췄습니다(한도 ${p.limit}개). 그 뒤의 파일은 찾지도 분석하지도 못했습니다. 생성된 디렉터리나 불필요한 디렉터리를 제외하면 나머지를 검사할 수 있습니다.`,
  ),
  walk_stopped_time: entry(
    { visited: "count" },
    (p) =>
      `The directory walk stopped after ${p.visited} entries because the time budget ran out; files beyond that point were not found or analyzed.`,
    (p) =>
      `시간 예산이 소진되어 디렉터리 탐색이 항목 ${p.visited}개에서 멈췄습니다. 그 뒤의 파일은 찾지도 분석하지도 못했습니다.`,
  ),
  large_files_skipped: entry(
    { count: "count" },
    (p) => `${p.count} source file(s) over 1 MiB were skipped.`,
    (p) => `1 MiB를 넘는 소스 파일 ${p.count}개를 건너뛰었습니다.`,
  ),
  symlinks_not_followed: entry(
    { count: "count", set: "hex" },
    (p) => `${p.count} symbolic link(s) were not followed (set ${p.set}).`,
    (p) => `심볼릭 링크 ${p.count}개를 따라가지 않았습니다(집합 ${p.set}).`,
  ),
  directories_unreadable: entry(
    { count: "count", set: "hex" },
    (p) =>
      `${p.count} director${plural(p.count, "y", "ies")} could not be read, so files below ${plural(p.count, "it were", "them were")} not analyzed (set ${p.set}).`,
    (p) => `디렉터리 ${p.count}개를 읽지 못해 그 아래 파일은 분석하지 못했습니다(집합 ${p.set}).`,
  ),
  config_budget_exceeded: entry(
    none,
    () =>
      "WARNING: the patterns in pgard.config.json exceeded the matching work limit (too many or too expensive patterns). Files after that point were scanned as if no pattern applied to them; simplify the patterns.",
    () =>
      "경고: pgard.config.json의 패턴이 매칭 작업 한도를 넘었습니다(패턴이 너무 많거나 비쌉니다). 그 뒤의 파일은 패턴이 적용되지 않은 것처럼 검사했으니 패턴을 단순하게 줄이세요.",
  ),
  orm_unsupported: entry(
    { library: "label" },
    (p) =>
      `${p.library} detected; raw query analysis for ${p.library} is not supported, so its queries were not evaluated (not a safe result).`,
    (p) =>
      `${p.library}를 감지했습니다. ${p.library}의 원시 쿼리 분석은 지원하지 않아 쿼리를 평가하지 않았습니다(안전하다는 결과가 아닙니다).`,
  ),
  language_files: entry(
    { count: "count", language: "label", method: METHOD_KEYS },
    (p) => `${p.count} ${p.language} file(s); ${methodEn(p.method)}.`,
    (p) => `${p.language} 파일 ${p.count}개. 방식: ${methodKo(p.method)}.`,
  ),
  language_no_files: entry(
    { language: "label" },
    (p) => `No ${p.language} files found.`,
    (p) => `${p.language} 파일이 없습니다.`,
  ),
  react_jsx_files: entry(
    { count: "count" },
    (p) => `${p.count} file(s) with JSX; analyzed with the JavaScript/TypeScript rules.`,
    (p) => `JSX가 있는 파일 ${p.count}개. JavaScript/TypeScript 규칙으로 분석했습니다.`,
  ),
  react_no_jsx: entry(
    none,
    () => "No JSX found.",
    () => "JSX가 없습니다.",
  ),
  heuristics_ran: entry(
    none,
    () =>
      "CSRF and brute-force checks are project-level heuristics (library imports and route names) and report suspected findings with low confidence.",
    () =>
      "CSRF와 무차별 대입 검사는 프로젝트 수준 휴리스틱(라이브러리 import와 라우트 이름)이며, 의심되는 항목을 낮은 신뢰도로 보고합니다.",
  ),
  heuristics_ran_partial: entry(
    none,
    () =>
      "CSRF and brute-force checks are project-level heuristics (library imports and route names) and report suspected findings with low confidence. Partial because a JavaScript, TypeScript or Vue area was partial.",
    () =>
      "CSRF와 무차별 대입 검사는 프로젝트 수준 휴리스틱(라이브러리 import와 라우트 이름)이며, 의심되는 항목을 낮은 신뢰도로 보고합니다. JavaScript, TypeScript 또는 Vue 영역이 일부만 검사되어 부분 결과입니다.",
  ),
  heuristics_not_run: entry(
    none,
    () =>
      "No JavaScript, TypeScript or Vue files were analyzed, so the CSRF and brute-force heuristics did not run.",
    () =>
      "분석한 JavaScript, TypeScript, Vue 파일이 없어 CSRF와 무차별 대입 휴리스틱을 실행하지 않았습니다.",
  ),
  python_other_categories: entry(
    none,
    () =>
      "Python cross-site scripting (Jinja2 |safe, Markup, mark_safe), SSRF, path traversal, cryptography and settings checks (DEBUG, SECRET_KEY, ALLOWED_HOSTS) are not implemented yet, so a clean Python result says nothing about them.",
    () =>
      "Python의 교차 사이트 스크립팅(Jinja2 |safe, Markup, mark_safe), SSRF, 경로 탐색, 암호화, 설정 검사(DEBUG, SECRET_KEY, ALLOWED_HOSTS)는 아직 구현되지 않았으므로, Python에서 아무것도 나오지 않았다는 결과는 이 항목들에 대해 아무것도 말해 주지 않습니다.",
  ),
  python_orm_unsupported: entry(
    { library: "label", count: "count" },
    (p) =>
      `${p.library} detected in ${p.count} Python file(s); its raw SQL APIs are not supported, so queries made through them were not evaluated (not a safe result).`,
    (p) =>
      `Python 파일 ${p.count}개에서 ${p.library}를 감지했습니다. 원시 SQL API는 지원하지 않아 이를 통한 쿼리는 평가하지 않았습니다(안전하다는 결과가 아닙니다).`,
  ),
  python_process_unsupported: entry(
    { library: "label", count: "count" },
    (p) =>
      `${p.library} detected in ${p.count} Python file(s); its process-running APIs are not supported, so commands run through it were not evaluated (not a safe result).`,
    (p) =>
      `Python 파일 ${p.count}개에서 ${p.library}를 감지했습니다. 프로세스 실행 API는 지원하지 않아 이를 통해 실행한 명령은 평가하지 않았습니다(안전하다는 결과가 아닙니다).`,
  ),

  // git-history
  history_no_commit: entry(
    none,
    () => "The repository has no commit to scan.",
    () => "검사할 커밋이 저장소에 없습니다.",
  ),
  history_revision_not_found: entry(
    { revision: "label" },
    (p) => `The revision to scan (${p.revision}) was not found in the repository.`,
    (p) => `검사할 리비전(${p.revision})을 저장소에서 찾지 못했습니다.`,
  ),
  history_tracked_files: entry(
    { count: "count", revision: "hex" },
    (p) =>
      `${p.count} tracked file(s) in commit ${p.revision}; Git objects only (untracked/ignored files are not read).`,
    (p) =>
      `커밋 ${p.revision}의 추적 파일 ${p.count}개. Git 객체만 읽었습니다(추적하지 않거나 무시된 파일은 읽지 않습니다).`,
  ),
  history_commits: entry(
    { count: "count", revision: "hex" },
    (p) =>
      `${p.count} commit(s) reachable from ${p.revision}; branches not merged into it are not scanned.`,
    (p) =>
      `${p.revision}에서 닿는 커밋 ${p.count}개. 여기에 병합되지 않은 브랜치는 검사하지 않습니다.`,
  ),

  // http-local
  web_authenticated_unavailable: entry(
    none,
    () => "authenticated browsing is not available in this MVP",
    () => "로그인한 상태의 탐색은 이 MVP에서 지원하지 않습니다",
  ),
  web_pages_checked: entry(
    { pages: "count" },
    (p) =>
      `${p.pages} page(s) checked. HSTS is not applicable to plain-http loopback and was not checked; GET requests can still change state in some apps.`,
    (p) =>
      `페이지 ${p.pages}개를 확인했습니다. HSTS는 평문 http 루프백에는 해당하지 않아 확인하지 않았고, 일부 앱에서는 GET 요청도 상태를 바꿀 수 있습니다.`,
  ),

  // dependencies
  dependencies_no_data_dir: entry(
    { packages: "count", lockfiles: "count" },
    (p) =>
      `No per-user data folder is available, so no OSV advisory data can be read; ${p.packages} package(s) from ${p.lockfiles} lockfile(s) were not checked.`,
    (p) =>
      `사용자별 데이터 폴더가 없어 OSV 권고 데이터를 읽을 수 없습니다. lockfile ${p.lockfiles}개의 패키지 ${p.packages}개를 확인하지 못했습니다.`,
  ),
  dependencies_data_missing: entry(
    { ecosystem: "label", packages: "count", lockfiles: "count" },
    (p) =>
      `OSV data for ${p.ecosystem} has not been downloaded, so ${p.packages} package(s) from ${p.lockfiles} lockfile(s) were not checked for known vulnerabilities. ${UPDATE_HINT_EN}`,
    (p) =>
      `${p.ecosystem}의 OSV 데이터를 내려받지 않아 lockfile ${p.lockfiles}개의 패키지 ${p.packages}개에서 알려진 취약점을 확인하지 못했습니다. ${UPDATE_HINT_KO}`,
  ),
  dependencies_data_damaged: entry(
    { ecosystem: "label", packages: "count", lockfiles: "count" },
    (p) =>
      `The stored OSV data for ${p.ecosystem} is damaged, so ${p.packages} package(s) from ${p.lockfiles} lockfile(s) were not checked. Run \`pgard advisories update\` to replace it.`,
    (p) =>
      `저장된 ${p.ecosystem}의 OSV 데이터가 손상되어 lockfile ${p.lockfiles}개의 패키지 ${p.packages}개를 확인하지 못했습니다. \`pgard advisories update\`를 실행해 교체하세요.`,
  ),
  dependencies_data_unreadable: entry(
    { ecosystem: "label" },
    (p) => `The OSV data for ${p.ecosystem} could not be read. ${UPDATE_HINT_EN}`,
    (p) => `${p.ecosystem}의 OSV 데이터를 읽을 수 없습니다. ${UPDATE_HINT_KO}`,
  ),
  dependencies_data_unverified: entry(
    { ecosystem: "label", packages: "count", lockfiles: "count" },
    (p) =>
      `The stored OSV data for ${p.ecosystem} could not be verified or read, so ${p.packages} package(s) from ${p.lockfiles} lockfile(s) were not checked. Run \`pgard advisories update\` to replace it.`,
    (p) =>
      `저장된 ${p.ecosystem}의 OSV 데이터를 검증하거나 읽을 수 없어 lockfile ${p.lockfiles}개의 패키지 ${p.packages}개를 확인하지 못했습니다. \`pgard advisories update\`를 실행해 교체하세요.`,
  ),
};

/** Every known code, for tests and tools. */
export const COVERAGE_NOTE_CODES: readonly string[] = Object.keys(COVERAGE_NOTE_CATALOG);

function hasOwn(object: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(object, key);
}

function isValid(kind: ParamKind, value: unknown): value is NoteParamValue {
  if (kind === "count") {
    return (
      typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= MAX_COUNT
    );
  }
  if (typeof value !== "string") return false;
  if (kind === "label") return LABEL.test(value);
  if (kind === "hex") return HEX.test(value);
  return kind.includes(value);
}

/**
 * The params of a known code when they all pass validation, or `null`. Unknown keys, a missing
 * required key, a wrong type, an out-of-range number or a string that is not a plain label all
 * make it `null`. The optional `walkStopped` marker (1) is the one key every code accepts.
 */
function validatedParams(
  spec: CatalogEntry,
  params: unknown,
): Record<string, NoteParamValue> | null {
  const given: Record<string, unknown> =
    params === undefined || params === null ? {} : (params as Record<string, unknown>);
  if (typeof given !== "object" || Array.isArray(given)) return null;
  const clean: Record<string, NoteParamValue> = {};
  for (const key of Object.keys(given)) {
    if (key === WALK_STOPPED_PARAM) {
      if (given[key] !== 1) return null;
      clean[key] = 1;
      continue;
    }
    if (!hasOwn(spec.params, key)) return null;
    const wanted = spec.params[key] as ParamSpec;
    const kind = typeof wanted === "object" && "kind" in wanted ? wanted.kind : wanted;
    if (!isValid(kind as ParamKind, given[key])) return null;
    clean[key] = given[key] as NoteParamValue;
  }
  for (const key of Object.keys(spec.params)) {
    const wanted = spec.params[key] as ParamSpec;
    const isOptional = typeof wanted === "object" && "kind" in wanted && wanted.optional;
    if (!isOptional && !hasOwn(clean, key)) return null;
  }
  return clean;
}

/**
 * The text of a coverage note in `language` from the catalog, or `null` when the code is absent,
 * unknown, or its params are invalid (the caller then uses the stored text).
 */
export function catalogNoteText(
  noteCode: unknown,
  noteParams: unknown,
  language: NoteLanguage,
): string | null {
  if (typeof noteCode !== "string" || !hasOwn(COVERAGE_NOTE_CATALOG, noteCode)) return null;
  const spec = COVERAGE_NOTE_CATALOG[noteCode] as CatalogEntry;
  const params = validatedParams(spec, noteParams);
  if (params === null) return null;
  const body = spec[language](params);
  if (params[WALK_STOPPED_PARAM] !== 1) return body;
  const prefix = (COVERAGE_NOTE_CATALOG["walk_stopped_early"] as CatalogEntry)[language](params);
  return `${prefix} ${body}`;
}

/**
 * The note of a coverage entry as a frontend should show it. English always shows the stored
 * text (it is what the analyzer wrote). Another language shows the catalog text when the entry
 * carries a known code with valid params, and the stored text otherwise (an old result, an
 * unknown code, tampered params). Returns `null` when the entry has no note.
 */
export function coverageNoteText(
  entry: { note: string | null; noteCode?: string | undefined; noteParams?: unknown },
  language: NoteLanguage,
): string | null {
  if (entry.note === null) return null;
  if (language === "en") return entry.note;
  return catalogNoteText(entry.noteCode, entry.noteParams, language) ?? entry.note;
}

/**
 * The fields an analyzer puts on a coverage entry: the English text from the catalog plus the
 * code and params. It throws on a code or params that the catalog would not accept, so a
 * producer bug fails in tests and never ships an untranslatable code.
 */
export function coverageNote(
  code: string,
  params: NoteParams = {},
): { note: string; noteCode: string; noteParams?: NoteParams } {
  const text = catalogNoteText(code, params, "en");
  if (text === null) throw new Error(`Invalid coverage note code or params: ${code}`);
  return Object.keys(params).length === 0
    ? { note: text, noteCode: code }
    : { note: text, noteCode: code, noteParams: { ...params } };
}

/**
 * Puts the "walk stopped early" prefix on an entry. The English text is the stored prefix plus
 * the old note, so it stays what it was; the code follows when the entry had a code (or no
 * note), otherwise the entry keeps English only for the part the catalog cannot name.
 */
export function prefixWalkStopped<
  T extends { note: string | null; noteCode?: string | undefined; noteParams?: NoteParams },
>(target: T): void {
  const hadNote = target.note !== null;
  target.note = hadNote ? `${WALK_STOPPED_PREFIX} ${target.note}` : WALK_STOPPED_PREFIX;
  if (!hadNote) {
    target.noteCode = "walk_stopped_early";
    delete target.noteParams;
  } else if (target.noteCode !== undefined) {
    target.noteParams = { ...(target.noteParams ?? {}), [WALK_STOPPED_PARAM]: 1 };
  }
}
