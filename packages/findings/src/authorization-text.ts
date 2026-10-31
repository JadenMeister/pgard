/**
 * Fixed texts for the authorization section of a report and of the CLI: the decision, the five
 * check ids, the check statuses and the reasons.
 *
 * Decision, ids and statuses are closed sets, so they have plain catalogs. Reasons are English
 * sentences the policy package writes, with a login, a repository or a count inside; they carry
 * no code, so the catalog below recognizes each fixed sentence by its exact shape and rewrites it
 * in Korean. A part taken from the sentence must be a plain name, number or short id (the
 * patterns below allow nothing else), and a reason that matches no pattern is shown as stored,
 * in English. Results written by any earlier version therefore render too. Every consumer still
 * escapes its output.
 */

import type { AuthorizationCheck, AuthorizationSummary } from "./contract.js";
import type { NoteLanguage } from "./coverage-notes.js";

const DECISION_LABELS: Record<NoteLanguage, Record<AuthorizationSummary["decision"], string>> = {
  en: { allowed: "Allowed", blocked: "Blocked" },
  ko: { allowed: "허용됨", blocked: "차단됨" },
};

const CHECK_LABELS: Record<NoteLanguage, Record<AuthorizationCheck["id"], string>> = {
  en: {
    repository: "Repository",
    github_identity: "GitHub identity",
    owner_approval: "Owner approval",
    current_access: "Current access",
    contribution: "Contribution",
  },
  ko: {
    repository: "저장소",
    github_identity: "GitHub 신원",
    owner_approval: "소유자 승인",
    current_access: "현재 접근 권한",
    contribution: "기여",
  },
};

const STATUS_LABELS: Record<NoteLanguage, Record<AuthorizationCheck["status"], string>> = {
  en: { passed: "Passed", failed: "Failed", unverifiable: "Unverifiable" },
  ko: { passed: "통과", failed: "실패", unverifiable: "확인 불가" },
};

function known<T extends string>(table: Record<T, string>, key: string): string | null {
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key as T] : null;
}

/** `허용됨` or `차단됨` (English: `Allowed` or `Blocked`); an unknown value comes back as is. */
export function authorizationDecisionLabel(decision: string, language: NoteLanguage): string {
  return known(DECISION_LABELS[language], decision) ?? decision;
}

/** A human label for a check id (`owner_approval` -> `소유자 승인`); an unknown id as is. */
export function authorizationCheckLabel(id: string, language: NoteLanguage): string {
  return known(CHECK_LABELS[language], id) ?? id;
}

/** `통과`, `실패` or `확인 불가` (English: Passed, Failed, Unverifiable); unknown as is. */
export function authorizationStatusLabel(status: string, language: NoteLanguage): string {
  return known(STATUS_LABELS[language], status) ?? status;
}

const NAME = "[A-Za-z0-9._-]{1,100}";
const FULL = `${NAME}/${NAME}`;
const TEXT = '[^"\\u0000-\\u001f\\u007f]{1,255}';
const NUM = "\\d{1,9}";
const SHA = "[0-9a-f]{12}";
const MAX_REASON_LENGTH = 1_000;

const CHECK_IDS_KO: Record<string, string> = {
  repository: "저장소",
  github_identity: "GitHub 신원",
  owner_approval: "소유자 승인",
  current_access: "현재 접근 권한",
  contribution: "기여",
};

interface ReasonPattern {
  /** Stable name, for tests. */
  id: string;
  /** The exact English sentence the policy writes, with the variable parts captured. */
  match: RegExp;
  ko: (groups: readonly string[]) => string;
}

const lit = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const re = (source: string): RegExp => new RegExp(`^${source}$`);

const guidanceKo = (branch: string): string =>
  `자격을 얻으려면 "${branch}"에 병합된 풀 리퀘스트를 만들거나, 커밋에 서명(GitHub에 Verified로 표시됨)하고 "${branch}"에 푸시하세요.`;

/** The fixed reasons of the authorization gate (policy and scan-core), each with its Korean text. */
export const AUTHORIZATION_REASON_PATTERNS: readonly ReasonPattern[] = [
  // scan-core
  {
    id: "internal_error",
    match: re(lit("Authorization could not be completed due to an internal error.")),
    ko: () => "내부 오류로 권한 확인을 끝내지 못했습니다.",
  },
  {
    id: "code_only_not_checked",
    match: re(
      lit(
        "Not checked: this was a code-only scan of the files on this computer. No authorization was proven.",
      ),
    ),
    ko: () =>
      "확인하지 않았습니다. 이 컴퓨터의 파일만 검사한 코드 전용 검사이며, 권한은 증명되지 않았습니다.",
  },
  // repository
  {
    id: "repository_ok",
    match: re(`Git repository with remote "(${NAME})" -> github\\.com/(${FULL})\\.`),
    ko: ([remote, repo]) => `Git 저장소이며 원격 "${remote}"이 github.com/${repo}를 가리킵니다.`,
  },
  {
    id: "no_remote",
    match: re(lit("The repository has no Git remote; a github.com remote is required.")),
    ko: () => "저장소에 Git 원격이 없습니다. github.com 원격이 필요합니다.",
  },
  {
    id: "no_github_remote",
    match: re(lit("No github.com remote was found.")),
    ko: () => "github.com 원격을 찾지 못했습니다.",
  },
  {
    id: "remotes_unreadable",
    match: re(lit("Could not list Git remotes.")),
    ko: () => "Git 원격 목록을 읽지 못했습니다.",
  },
  {
    id: "remote_has_no_url",
    match: re(`Remote "(${NAME})" has no URL\\.`),
    ko: ([remote]) => `원격 "${remote}"에 URL이 없습니다.`,
  },
  {
    id: "remote_not_github",
    match: re(
      `Remote "(${NAME})" is not a recognizable github\\.com repository URL; only github\\.com remotes are supported\\.`,
    ),
    ko: ([remote]) =>
      `원격 "${remote}"은 알아볼 수 있는 github.com 저장소 URL이 아닙니다. github.com 원격만 지원합니다.`,
  },
  {
    id: "remote_ambiguous",
    match: re(
      lit(
        "Git remotes point to different GitHub repositories; the target repository is ambiguous.",
      ),
    ),
    ko: () => "Git 원격이 서로 다른 GitHub 저장소를 가리켜 대상 저장소가 모호합니다.",
  },
  {
    id: "no_commit_history",
    match: re(lit("The repository has no valid commit history.")),
    ko: () => "저장소에 유효한 커밋 기록이 없습니다.",
  },
  {
    id: "repository_changed",
    match: re(lit("The repository changed since you confirmed it.")),
    ko: () => "확인한 뒤 저장소가 바뀌었습니다.",
  },
  {
    id: "not_evaluated",
    match: re(`Not evaluated because the (${NAME}) check did not pass\\.`),
    ko: ([id]) => `${CHECK_IDS_KO[id ?? ""] ?? id} 확인이 통과하지 못해 평가하지 않았습니다.`,
  },
  // github identity
  {
    id: "signed_in",
    match: re(`Signed in to GitHub as (${NAME})\\.`),
    ko: ([login]) => `GitHub에 ${login} 계정으로 로그인했습니다.`,
  },
  {
    id: "sign_in_denied",
    match: re(lit("GitHub sign-in was denied.")),
    ko: () => "GitHub 로그인이 거부되었습니다.",
  },
  {
    id: "sign_in_expired",
    match: re(lit("The GitHub sign-in code expired before it was approved.")),
    ko: () => "승인되기 전에 GitHub 로그인 코드가 만료되었습니다.",
  },
  {
    id: "sign_in_cancelled",
    match: re(lit("GitHub sign-in was cancelled.")),
    ko: () => "GitHub 로그인이 취소되었습니다.",
  },
  {
    id: "identity_unexpected_error",
    match: re(lit("GitHub identity could not be verified due to an unexpected error.")),
    ko: () => "예기치 않은 오류로 GitHub 신원을 확인하지 못했습니다.",
  },
  {
    id: "session_gone",
    match: re(
      lit("The GitHub sign-in is no longer available, so owner approval was not checked again."),
    ),
    ko: () => "GitHub 로그인을 더 이상 사용할 수 없어 소유자 승인을 다시 확인하지 못했습니다.",
  },
  // current access
  {
    id: "access_ok",
    match: re(`The signed-in user currently has access to (${FULL})\\.`),
    ko: ([repo]) => `로그인한 사용자는 현재 ${repo}에 접근할 수 있습니다.`,
  },
  {
    id: "access_none",
    match: re(`The signed-in user has no read access to (${FULL})\\.`),
    ko: ([repo]) => `로그인한 사용자에게 ${repo}의 읽기 권한이 없습니다.`,
  },
  {
    id: "access_permissions_unreported",
    match: re(lit("GitHub did not report the user's permissions for this repository.")),
    ko: () => "GitHub가 이 저장소에 대한 사용자 권한을 알려 주지 않았습니다.",
  },
  {
    id: "access_not_found",
    match: re(
      `GitHub returned no access to github\\.com/(${FULL})\\. For a private repository this usually means the PGARD GitHub App is not installed for it, or your account has no access\\.`,
    ),
    ko: ([repo]) =>
      `GitHub가 github.com/${repo}에 대한 접근을 허용하지 않았습니다. 비공개 저장소라면 대개 PGARD GitHub App이 설치되어 있지 않거나 계정에 접근 권한이 없다는 뜻입니다.`,
  },
  {
    id: "access_not_found_all_repositories",
    match: re(
      `GitHub returned no access to github\\.com/(${FULL})\\. The PGARD GitHub App is already installed on the owner account for all repositories, so adding the repository will not help: your account probably has no access, the repository does not exist, or the git remote is wrong\\.`,
    ),
    ko: ([repo]) =>
      `GitHub가 github.com/${repo}에 대한 접근을 허용하지 않았습니다. PGARD GitHub App이 소유자 계정의 모든 저장소에 이미 설치되어 있어 저장소를 추가해도 소용없습니다. 계정에 접근 권한이 없거나, 저장소가 없거나, git 원격이 잘못되었을 가능성이 큽니다.`,
  },
  // owner approval
  {
    id: "owner_installed_personal",
    match: re(
      `The PGARD GitHub App is installed by the owner account "(${NAME})" and includes (${FULL})\\.`,
    ),
    ko: ([owner, repo]) =>
      `소유자 계정 "${owner}"이 PGARD GitHub App을 설치했고 ${repo}가 포함되어 있습니다.`,
  },
  {
    id: "owner_installation_excludes_repository",
    match: re(`The owner's PGARD GitHub App installation does not include (${FULL})\\.`),
    ko: ([repo]) => `소유자의 PGARD GitHub App 설치에 ${repo}가 포함되어 있지 않습니다.`,
  },
  {
    id: "owner_no_installation",
    match: re(
      `No PGARD GitHub App installation on the owner account "(${NAME})" was found for (${FULL})\\.`,
    ),
    ko: ([owner, repo]) =>
      `${repo}에 대해 소유자 계정 "${owner}"의 PGARD GitHub App 설치를 찾지 못했습니다.`,
  },
  {
    id: "owner_type_unknown",
    match: re(lit("The repository owner type could not be determined.")),
    ko: () => "저장소 소유자의 유형을 알 수 없습니다.",
  },
  {
    id: "org_installation_excludes_repository",
    match: re(
      `The PGARD GitHub App installation on the organization "(${NAME})" does not include (${FULL})\\. An owner of (${NAME}) must add the repository to the installation\\.`,
    ),
    ko: ([org, repo, owner]) =>
      `조직 "${org}"의 PGARD GitHub App 설치에 ${repo}가 포함되어 있지 않습니다. ${owner}의 소유자가 설치에 이 저장소를 추가해야 합니다.`,
  },
  {
    id: "org_no_installation",
    match: re(
      `No PGARD GitHub App installation on the organization "(${NAME})" was found for (${FULL})\\. An owner of (${NAME}) must install the App on the organization and include the repository\\.`,
    ),
    ko: ([org, repo, owner]) =>
      `${repo}에 대해 조직 "${org}"의 PGARD GitHub App 설치를 찾지 못했습니다. ${owner}의 소유자가 조직에 App을 설치하고 이 저장소를 포함해야 합니다.`,
  },
  {
    id: "org_owner_ok",
    match: re(
      `(${NAME}) is an owner of the organization "(${NAME})", and the organization's PGARD GitHub App installation includes (${FULL})\\.`,
    ),
    ko: ([login, org, repo]) =>
      `${login}은(는) 조직 "${org}"의 소유자이며, 조직의 PGARD GitHub App 설치에 ${repo}가 포함되어 있습니다.`,
  },
  {
    id: "org_membership_pending",
    match: re(
      `(${NAME})'s membership in (${NAME}) is pending, not active; an organization owner with an active membership must run the scan\\.`,
    ),
    ko: ([login, org]) =>
      `${login}의 ${org} 멤버십이 활성이 아니라 대기 중입니다. 활성 멤버십을 가진 조직 소유자가 검사를 실행해야 합니다.`,
  },
  {
    id: "org_not_owner",
    match: re(
      `(${NAME}) is not an owner of (${NAME}) \\(role: ([A-Za-z_]{1,30})\\); an organization owner must run the scan\\.`,
    ),
    ko: ([login, org, role]) =>
      `${login}은(는) ${org}의 소유자가 아닙니다(역할: ${role}). 조직 소유자가 검사를 실행해야 합니다.`,
  },
  // contribution
  {
    id: "contribution_owner_personal",
    match: re(
      `(${NAME}) owns (${FULL}) \\(verified by GitHub account id\\); a separate contribution is not required\\.`,
    ),
    ko: ([login, repo]) =>
      `${login}은(는) ${repo}의 소유자입니다(GitHub 계정 id로 확인). 별도의 기여는 필요하지 않습니다.`,
  },
  {
    id: "contribution_owner_org",
    match: re(
      `(${NAME}) is an owner of the organization "(${NAME})"; a separate contribution is not required\\.`,
    ),
    ko: ([login, org]) =>
      `${login}은(는) 조직 "${org}"의 소유자입니다. 별도의 기여는 필요하지 않습니다.`,
  },
  {
    id: "contribution_no_commits",
    match: re(
      `No local commits were found to check for a contribution\\. To qualify, get a pull request merged into "(${TEXT})", or sign your commits \\(GitHub shows them as Verified\\) and push them to "\\1"\\.`,
    ),
    ko: ([branch]) => `기여를 확인할 로컬 커밋이 없습니다. ${guidanceKo(branch ?? "")}`,
  },
  {
    id: "contribution_in_default_branch_pr",
    match: re(
      `Commit (${SHA}) is in the default branch "(${TEXT})" \\(pull request #(${NUM}) by (${NAME}) merged into "(${TEXT})"\\)\\.`,
    ),
    ko: ([sha, branch, number, login]) =>
      `커밋 ${sha}이(가) 기본 브랜치 "${branch}"에 있습니다(${login}의 풀 리퀘스트 #${number}이(가) 병합됨).`,
  },
  {
    id: "contribution_in_default_branch_signed",
    match: re(
      `Commit (${SHA}) is in the default branch "(${TEXT})" \\(signature-verified commit by (${NAME})\\)\\.`,
    ),
    ko: ([sha, branch, login]) =>
      `커밋 ${sha}이(가) 기본 브랜치 "${branch}"에 있습니다(${login}의 서명 확인된 커밋).`,
  },
  {
    id: "contribution_history_unreadable",
    match: re(lit("Could not read local Git history to find contribution candidates.")),
    ko: () => "기여 후보를 찾기 위한 로컬 Git 기록을 읽지 못했습니다.",
  },
  {
    id: "contribution_repository_name",
    match: re(lit("GitHub returned an unexpected repository name.")),
    ko: () => "GitHub가 예상하지 못한 저장소 이름을 돌려주었습니다.",
  },
];

/**
 * A reason as the report and the CLI should show it. English shows the stored text. Korean shows
 * the Korean text when the reason is one of the fixed sentences above, and the stored English
 * text otherwise (`translated` is false then, so a frontend can mark it as the scan's own text).
 */
export function authorizationReasonText(
  reason: string,
  language: NoteLanguage,
): { text: string; translated: boolean } {
  if (language === "en" || reason.length > MAX_REASON_LENGTH) {
    return { text: reason, translated: false };
  }
  for (const pattern of AUTHORIZATION_REASON_PATTERNS) {
    const found = pattern.match.exec(reason);
    if (found !== null) return { text: pattern.ko(found.slice(1)), translated: true };
  }
  return { text: reason, translated: false };
}

/**
 * The authorization section as text rows for a report: English keeps the stored ids, statuses
 * and reasons as they were, Korean uses the fixed catalogs above. One helper for the HTML and
 * the PDF report, so the two never differ.
 */
export function authorizationReportRows(
  summary: AuthorizationSummary,
  language: NoteLanguage,
): { decision: string; checks: Array<{ id: string; status: string; reason: string }> } {
  if (language === "en") {
    return {
      decision: summary.decision,
      checks: summary.checks.map(({ id, status, reason }) => ({ id, status, reason })),
    };
  }
  return {
    decision: authorizationDecisionLabel(summary.decision, language),
    checks: summary.checks.map((check) => ({
      id: authorizationCheckLabel(check.id, language),
      status: authorizationStatusLabel(check.status, language),
      reason: authorizationReasonText(check.reason, language).text,
    })),
  };
}
