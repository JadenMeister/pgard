/**
 * Korean wording of the standards-map reasons that `@pgard/findings` stores as English text in
 * the result (`StandardCoverageEntry.reason`). The result has no structured code for them and its
 * schema stays as it is, so each segment of the reason ("; " separated) is matched against the
 * known sentence shapes. A segment that is not recognized stays as stored, so a reason is never
 * lost or reworded wrongly.
 */

const SCOPE_WHY: Readonly<Record<string, string>> = {
  "scope not selected": "범위를 선택하지 않음",
  "areas could not run": "영역을 실행하지 못함",
};

function whyKo(why: string): string {
  return SCOPE_WHY[why] ?? why;
}

/** "(3 files)" / "(1 file)" after a language name becomes "(3개 파일)". */
function languageListKo(text: string): string {
  return text.replace(/\((\d+) files?\)/g, "($1개 파일)");
}

const HINT_EN =
  ' (files that are not yours to scan can be left out with "exclude" in pgard.config.json)';
const HINT_KO = ' (검사 대상이 아닌 파일은 pgard.config.json의 "exclude"로 제외할 수 있음)';

const NO_RULE_RAN =
  /^no mapped rule ran \((.*?): ((?:\S+ (?:scope not selected|areas could not run)(?:, )?)+)\)$/;

/** Text up to the next "; " (the separator of two sentences), so a whole-reason match never spans two. */
const ONE = "((?:(?!; ).)*)";

function segmentKo(segment: string): string {
  if (segment === "no rules") return "규칙 없음";
  if (segment === "mapped rules ran to completion") return "매핑된 규칙이 끝까지 실행됨";
  if (segment === "no mapped area ran to completion") return "끝까지 실행된 매핑 영역이 없음";
  let match = NO_RULE_RAN.exec(segment);
  if (match !== null) {
    const why = (match[2] ?? "")
      .split(", ")
      .map((part) => {
        const space = part.indexOf(" ");
        return `${part.slice(0, space)} ${whyKo(part.slice(space + 1))}`;
      })
      .join(", ");
    return `실행된 매핑 규칙이 없음 (${match[1]}: ${why})`;
  }
  match = new RegExp(`^partial areas: ${ONE}$`).exec(segment);
  if (match !== null) return `일부만 실행된 영역: ${match[1]}`;
  match = /^(\S+) rules not run: (scope not selected|areas could not run)$/.exec(segment);
  if (match !== null) return `${match[1]} 규칙 실행 안 됨: ${whyKo(match[2] ?? "")}`;
  match = new RegExp(`^examined 0 targets: ${ONE}$`).exec(segment);
  if (match !== null) return `살펴본 대상이 0개: ${match[1]}`;
  match = new RegExp(`^no completed mapped rule covers ${ONE}$`).exec(segment);
  if (match !== null) {
    let rest = match[1] ?? "";
    let hint = "";
    if (rest.endsWith(HINT_EN)) {
      rest = rest.slice(0, -HINT_EN.length);
      hint = HINT_KO;
    }
    return `끝까지 실행된 매핑 규칙이 다루지 못하는 언어: ${languageListKo(rest)}${hint}`;
  }
  match = /^rules not in the rule catalog ran \((.*)\), so the mapping may be incomplete$/.exec(
    segment,
  );
  if (match !== null)
    return `규칙 목록에 없는 규칙이 실행됨 (${match[1]}), 매핑이 불완전할 수 있음`;
  return segment;
}

/** The reason of a standards-map row in the report language (English is returned unchanged). */
export function standardReasonText(reason: string, lang: string): string {
  if (lang !== "ko") return reason;
  // The whole sentence first, so a sentence that itself holds "; " is not cut in the middle.
  const whole = segmentKo(reason);
  if (whole !== reason) return whole;
  return reason.split("; ").map(segmentKo).join("; ");
}
