import { isCodeOnlyResult, type RuleLocale, type ScanResult } from "@pgard/findings";

/**
 * The "not authorized" label of a code-only result (JSON 1.7 `scanBasis.mode: "code_only"`):
 * a banner on every report page and a cover block. Never "verified" wording.
 */
export interface CodeOnlyLabel {
  /** One line, repeated on every page. */
  banner: string;
  title: string;
  body: string;
  /** Why authorization was not verified (from `scanBasis.reason`). */
  reason: string;
}

const BANNER: Record<RuleLocale, string> = {
  en: "Not authorized: code-only scan. Authorization was not verified; only the current files were checked.",
  ko: "권한 미확인: 코드 전용 검사. 권한을 확인하지 않았으며 현재 파일만 검사했습니다.",
};

const TITLE: Record<RuleLocale, string> = {
  en: "Not authorized: code-only scan",
  ko: "권한 미확인: 코드 전용 검사",
};

const BODY: Record<RuleLocale, string> = {
  en: "PGARD did not prove that you may scan this code. It checked the files on this computer only: no Git history, no web checks, and the result was not saved. This report is not an authorized audit.",
  ko: "이 코드를 검사해도 된다는 권한을 PGARD가 확인하지 않았습니다. 이 컴퓨터에 있는 파일만 검사했으며, Git 기록과 웹 검사는 하지 않았고 결과도 저장하지 않았습니다. 이 보고서는 권한이 확인된 감사가 아닙니다.",
};

const REASONS: Record<RuleLocale, Record<string, string>> = {
  en: {
    no_approval: "The authorization gate did not allow a full scan of this repository.",
    not_checked: "Authorization was not checked for this scan.",
    no_github_remote:
      "This folder has no GitHub remote, so owner approval cannot be checked (it is proven through GitHub only).",
    not_a_git_repository:
      "This folder is not a Git repository, so there is no repository to authorize.",
    offline: "Authorization could not be checked offline.",
  },
  ko: {
    no_approval: "권한 확인에서 이 저장소의 전체 검사가 허용되지 않았습니다.",
    not_checked: "이 검사에서는 권한을 확인하지 않았습니다.",
    no_github_remote:
      "이 폴더에는 GitHub remote가 없어 소유자 승인을 확인할 수 없습니다(승인은 GitHub로만 확인합니다).",
    not_a_git_repository: "이 폴더는 Git 저장소가 아니어서 권한을 확인할 저장소가 없습니다.",
    offline: "오프라인이라 권한을 확인할 수 없었습니다.",
  },
};

/** The label of a code-only result, or `null` for any other result. */
export function codeOnlyLabel(
  result: Pick<ScanResult, "scanBasis">,
  lang: RuleLocale,
): CodeOnlyLabel | null {
  if (!isCodeOnlyResult(result)) return null;
  const code = result.scanBasis?.reason ?? "not_checked";
  return {
    banner: BANNER[lang],
    title: TITLE[lang],
    body: BODY[lang],
    // An unknown (newer) reason code is shown as the generic "not checked" sentence.
    reason: REASONS[lang][code] ?? REASONS[lang].not_checked ?? "",
  };
}
