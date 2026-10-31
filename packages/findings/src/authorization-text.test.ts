import { describe, expect, it } from "vitest";
import {
  AUTHORIZATION_REASON_PATTERNS,
  authorizationCheckLabel,
  authorizationDecisionLabel,
  authorizationReasonText,
  authorizationReportRows,
  authorizationStatusLabel,
} from "./authorization-text.js";
import { AUTHORIZATION_CHECK_IDS } from "./contract.js";

/** One real English reason per pattern id, as the policy writes it. */
const SAMPLES: Record<string, string> = {
  internal_error: "Authorization could not be completed due to an internal error.",
  code_only_not_checked:
    "Not checked: this was a code-only scan of the files on this computer. No authorization was proven.",
  repository_ok: 'Git repository with remote "origin" -> github.com/acme/app.',
  no_remote: "The repository has no Git remote; a github.com remote is required.",
  no_github_remote: "No github.com remote was found.",
  remotes_unreadable: "Could not list Git remotes.",
  remote_has_no_url: 'Remote "origin" has no URL.',
  remote_not_github:
    'Remote "origin" is not a recognizable github.com repository URL; only github.com remotes are supported.',
  remote_ambiguous:
    "Git remotes point to different GitHub repositories; the target repository is ambiguous.",
  no_commit_history: "The repository has no valid commit history.",
  repository_changed: "The repository changed since you confirmed it.",
  not_evaluated: "Not evaluated because the repository check did not pass.",
  signed_in: "Signed in to GitHub as octocat.",
  sign_in_denied: "GitHub sign-in was denied.",
  sign_in_expired: "The GitHub sign-in code expired before it was approved.",
  sign_in_cancelled: "GitHub sign-in was cancelled.",
  identity_unexpected_error: "GitHub identity could not be verified due to an unexpected error.",
  session_gone:
    "The GitHub sign-in is no longer available, so owner approval was not checked again.",
  access_ok: "The signed-in user currently has access to acme/app.",
  access_none: "The signed-in user has no read access to acme/app.",
  access_permissions_unreported:
    "GitHub did not report the user's permissions for this repository.",
  access_not_found:
    "GitHub returned no access to github.com/acme/app. For a private repository this usually means the PGARD GitHub App is not installed for it, or your account has no access.",
  access_not_found_all_repositories:
    "GitHub returned no access to github.com/acme/app. The PGARD GitHub App is already installed on the owner account for all repositories, so adding the repository will not help: your account probably has no access, the repository does not exist, or the git remote is wrong.",
  owner_installed_personal:
    'The PGARD GitHub App is installed by the owner account "acme" and includes acme/app.',
  owner_installation_excludes_repository:
    "The owner's PGARD GitHub App installation does not include acme/app.",
  owner_no_installation:
    'No PGARD GitHub App installation on the owner account "acme" was found for acme/app.',
  owner_type_unknown: "The repository owner type could not be determined.",
  org_installation_excludes_repository:
    'The PGARD GitHub App installation on the organization "acme" does not include acme/app. An owner of acme must add the repository to the installation.',
  org_no_installation:
    'No PGARD GitHub App installation on the organization "acme" was found for acme/app. An owner of acme must install the App on the organization and include the repository.',
  org_owner_ok:
    'octocat is an owner of the organization "acme", and the organization\'s PGARD GitHub App installation includes acme/app.',
  org_membership_pending:
    "octocat's membership in acme is pending, not active; an organization owner with an active membership must run the scan.",
  org_not_owner:
    "octocat is not an owner of acme (role: member); an organization owner must run the scan.",
  contribution_owner_personal_linked:
    "octocat owns acme/app (verified by GitHub account id); a separate contribution is not required. Local HEAD is linked to acme/app by commit 0123456789ab.",
  contribution_owner_org_linked:
    'octocat is an owner of the organization "acme"; a separate contribution is not required. Local HEAD is linked to acme/app by commit 0123456789ab.',
  contribution_unlinked:
    "None of the last 2 local commits is on acme/app's default branch \"main\"; the local code can't be tied to this repository. Push or pull so local history shares a commit with the default branch.",
  contribution_unqualified_capped:
    'No qualifying contribution among the 1 commits examined (of 2 local commits). A pull request by the signed-in user merged into the default branch, or a signature-verified commit by them in the default branch, is required. To qualify, get a pull request merged into "main", or sign your commits (GitHub shows them as Verified) and push them to "main".',
  contribution_unqualified:
    'No qualifying contribution found among 2 local commits. A pull request by the signed-in user merged into the default branch, or a signature-verified commit by them in the default branch, is required; author name/email, unmerged PRs, PRs into other branches and local-only commits do not count. To qualify, get a pull request merged into "main", or sign your commits (GitHub shows them as Verified) and push them to "main".',
  remote_config_rewrite:
    "The repository config rewrites remote URLs (url.*.insteadOf or url.*.pushInsteadOf), so its GitHub identity can't be confirmed; remove the rewrite and check again.",
  remote_config_unreadable:
    "Could not read the Git remote URLs from the repository config; check that .git/config and any included files are readable regular files, then check again.",
  remote_name_unsupported: "A Git remote has an unsupported name.",
  org_remote_mismatch:
    'The Git remote names the organization "Acme", but GitHub reports the owner as "acme". Update the remote to github.com/acme/app so the organization can be verified.',
  org_installation_account_mismatch:
    'The PGARD GitHub App installation for the organization "acme" reports the account "other". Owner approval cannot be verified.',
  membership_org_mismatch:
    'GitHub returned a membership for the organization "other" instead of "acme". Owner approval cannot be verified.',
  membership_user_mismatch:
    'GitHub returned the acme membership of "other" instead of the signed-in user octocat. Owner approval cannot be verified.',
  membership_state_unexpected:
    "GitHub reported an unexpected membership state for octocat in acme; an organization owner with an active membership must run the scan.",
  membership_forbidden:
    "GitHub refused to show octocat's membership in acme (403): the PGARD GitHub App needs the organization permission Members: Read-only, approved by an owner of acme.",
  membership_not_found:
    "GitHub did not return octocat's membership in acme (404): octocat may not be a member, or the PGARD GitHub App cannot read the organization's members. An owner of acme must run the scan, with the App's Members: Read-only permission approved.",
  membership_rate_limited:
    "Could not read octocat's membership in acme: the GitHub API rate limit was reached. Try again later.",
  membership_unexpected_error:
    "Could not read octocat's membership in acme due to an unexpected error.",
  api_unexpected_error: "Could not list GitHub App installations due to an unexpected error.",
  contribution_no_commits:
    'No local commits were found to check for a contribution. To qualify, get a pull request merged into "main", or sign your commits (GitHub shows them as Verified) and push them to "main".',
  contribution_in_default_branch_pr:
    'Commit 0123456789ab is in the default branch "main" (pull request #42 by octocat merged into "main").',
  contribution_in_default_branch_signed:
    'Commit 0123456789ab is in the default branch "main" (signature-verified commit by octocat).',
  contribution_history_unreadable:
    "Could not read local Git history to find contribution candidates.",
  contribution_repository_name: "GitHub returned an unexpected repository name.",
};

const HANGUL = /[가-힣]/;

describe("authorization labels", () => {
  it("translates the decision, every check id and every status from fixed catalogs", () => {
    expect(authorizationDecisionLabel("allowed", "ko")).toBe("허용됨");
    expect(authorizationDecisionLabel("blocked", "ko")).toBe("차단됨");
    expect(AUTHORIZATION_CHECK_IDS.map((id) => authorizationCheckLabel(id, "ko"))).toEqual([
      "저장소",
      "GitHub 신원",
      "소유자 승인",
      "현재 접근 권한",
      "기여",
    ]);
    expect(
      (["passed", "failed", "unverifiable"] as const).map((s) => authorizationStatusLabel(s, "ko")),
    ).toEqual(["통과", "실패", "확인 불가"]);
    for (const id of AUTHORIZATION_CHECK_IDS) {
      expect(authorizationCheckLabel(id, "en")).not.toBe(id);
    }
  });

  it("returns an unknown value as it is, never from the prototype", () => {
    expect(authorizationDecisionLabel("maybe", "ko")).toBe("maybe");
    expect(authorizationCheckLabel("constructor", "ko")).toBe("constructor");
    expect(authorizationStatusLabel("__proto__", "ko")).toBe("__proto__");
  });
});

describe("authorization reasons", () => {
  it("has a sample for every pattern, and each sample is translated to Korean", () => {
    expect(AUTHORIZATION_REASON_PATTERNS.map((p) => p.id).sort()).toEqual(
      Object.keys(SAMPLES).sort(),
    );
    for (const pattern of AUTHORIZATION_REASON_PATTERNS) {
      const sample = SAMPLES[pattern.id] as string;
      const shown = authorizationReasonText(sample, "ko");
      expect(shown.translated, pattern.id).toBe(true);
      expect(shown.text, pattern.id).toMatch(HANGUL);
      expect(shown.text, pattern.id).not.toBe(sample);
      expect(authorizationReasonText(sample, "en")).toEqual({ text: sample, translated: false });
    }
  });

  it("matches each sample with exactly one pattern", () => {
    for (const [id, sample] of Object.entries(SAMPLES)) {
      const hits = AUTHORIZATION_REASON_PATTERNS.filter((p) => p.match.test(sample));
      expect(
        hits.map((p) => p.id),
        id,
      ).toEqual([id]);
    }
  });

  it("keeps the stored English for a reason it does not know", () => {
    expect(authorizationReasonText("Owner approved", "ko")).toEqual({
      text: "Owner approved",
      translated: false,
    });
  });

  it("translates a check id in a reason only from the fixed list, never from a prototype key", () => {
    for (const id of ["constructor", "__proto__", "toString", "hasOwnProperty"]) {
      const reason = `Not evaluated because the ${id} check did not pass.`;
      expect(authorizationReasonText(reason, "ko")).toEqual({ text: reason, translated: false });
    }
    expect(
      authorizationReasonText("Not evaluated because the owner_approval check did not pass.", "ko"),
    ).toEqual({ text: "소유자 승인 확인이 통과하지 못해 평가하지 않았습니다.", translated: true });
  });

  it("uses neutral particles after a name that may end in a consonant or a vowel", () => {
    for (const reason of [
      'Git repository with remote "origin" -> github.com/acme/app.',
      'The PGARD GitHub App is installed by the owner account "acme" and includes acme/app.',
    ]) {
      expect(authorizationReasonText(reason, "ko").text).toMatch(/이\(가\)/);
    }
  });

  it("does not rewrite a reason whose name part is not a plain name (no markup)", () => {
    for (const reason of [
      "Signed in to GitHub as <img src=x onerror=alert(1)>.",
      'Git repository with remote "o<b>" -> github.com/a/b.',
      "The signed-in user currently has access to a/<script>.",
      `Signed in to GitHub as ${"a".repeat(500)}.`,
    ]) {
      expect(authorizationReasonText(reason, "ko")).toEqual({ text: reason, translated: false });
    }
    // A translated reason carries only the allowed name characters.
    const shown = authorizationReasonText("Signed in to GitHub as octo-cat_1.", "ko");
    expect(shown.text).toBe("GitHub에 octo-cat_1 계정으로 로그인했습니다.");
  });

  it("gives the report rows: English as stored, Korean from the catalogs", () => {
    const summary = {
      decision: "allowed" as const,
      checks: [
        {
          id: "owner_approval" as const,
          status: "passed" as const,
          reason:
            'The PGARD GitHub App is installed by the owner account "acme" and includes acme/app.',
        },
        { id: "contribution" as const, status: "failed" as const, reason: "Something new." },
      ],
    };
    expect(authorizationReportRows(summary, "en")).toEqual({
      decision: "allowed",
      checks: summary.checks,
    });
    expect(authorizationReportRows(summary, "ko")).toEqual({
      decision: "허용됨",
      checks: [
        {
          id: "소유자 승인",
          status: "통과",
          reason:
            '소유자 계정 "acme"이(가) PGARD GitHub App을 설치했고 acme/app이(가) 포함되어 있습니다.',
        },
        { id: "기여", status: "실패", reason: "Something new." },
      ],
    });
  });
});
