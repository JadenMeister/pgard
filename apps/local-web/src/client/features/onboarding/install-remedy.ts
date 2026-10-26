import type { InstallRemedyDto, OwnerApprovalRecheckDto } from "../../../shared/api-types";
import { isGitHubUrl } from "../../components/github/device-code";
import { en } from "../../i18n/en";
import type { Messages } from "../../i18n/types";

/**
 * Same timing as the CLI: re-check every 5 s, for up to 10 minutes. The server enforces both (at
 * most one re-check per 5 s, only within 10 minutes of the check that offered the install).
 */
export const INSTALL_POLL_INTERVAL_MS = 5_000;

/** English texts; the panel reads the same wording from the active catalog. */
export const INSTALL_BUTTON_LABEL = en.install.button;
export const WAITING_FOR_INSTALL_TEXT = en.install.waiting;
export const INSTALL_WAIT_TIMED_OUT_TEXT = en.install.timedOut;

export type InstallRemedyView =
  /** The user can install it: show the button and wait. */
  | { kind: "install"; url: string; text: string }
  /** Someone else must install it: show the shareable link, no waiting. */
  | { kind: "ask_owner"; url: string; text: string }
  /** No link can be offered. */
  | { kind: "unavailable"; text: string };

/** What the authorization panel shows for a remedy; the same wording as the CLI. */
export function describeInstallRemedy(
  remedy: InstallRemedyDto,
  repo: string | null = null,
  m: Messages = en,
): InstallRemedyView {
  const account = remedy.account.login;
  const target = repo ?? m.install.thisRepository;
  if (remedy.url === null || !isGitHubUrl(remedy.url)) {
    return {
      kind: "unavailable",
      text: remedy.unavailableReason ?? m.install.noLink,
    };
  }
  if (remedy.canApprove === "no" && remedy.missing === "repository_access") {
    return {
      kind: "ask_owner",
      url: remedy.url,
      text: m.install.repoAccessAskOwner(account, target),
    };
  }
  if (remedy.canApprove === "no") {
    return {
      kind: "ask_owner",
      url: remedy.url,
      text: m.install.askOwner(account),
    };
  }
  if (remedy.missing === "repository_access") {
    const lead = m.install.repoAccessLead(account, target);
    const steps = m.install.repoAccessSteps(target);
    return {
      kind: "install",
      url: remedy.url,
      text:
        remedy.canApprove === "yes"
          ? `${lead} ${m.install.repoAccessOwner(target)} ${steps}`
          : `${lead} ${m.install.repoAccessMaybeOwner(account, target, remedy.url)} ${steps}`,
    };
  }
  if (remedy.missing === "access") {
    return {
      kind: "install",
      url: remedy.url,
      text: `${m.install.accessLead} ${m.install.maybeOwner(account, remedy.url)} ${m.install.accessPage(target)}`,
    };
  }
  if (remedy.canApprove === "unknown") {
    // Same wording as the CLI: GitHub would not show the membership before the App is installed.
    return {
      kind: "install",
      url: remedy.url,
      text: m.install.maybeOwner(account, remedy.url),
    };
  }
  return {
    kind: "install",
    url: remedy.url,
    text: m.install.owner(account),
  };
}

/** The button and waiting texts for a remedy: an install, or adding a repository to one. */
export function installTexts(
  remedy: InstallRemedyDto,
  m: Messages = en,
): { button: string; waiting: string; timedOut: string } {
  return remedy.missing === "repository_access"
    ? {
        button: m.install.repoAccessButton,
        waiting: m.install.repoAccessWaiting,
        timedOut: m.install.repoAccessTimedOut,
      }
    : { button: m.install.button, waiting: m.install.waiting, timedOut: m.install.timedOut };
}

/**
 * After a re-check: run the full authorization again once owner approval passed or no longer
 * fails for the missing installation; otherwise keep waiting. The re-check is never a pass.
 */
export function nextInstallStep(recheck: OwnerApprovalRecheckDto): "reverify" | "keep_waiting" {
  return recheck.status === "passed" || recheck.remedy === null ? "reverify" : "keep_waiting";
}

/**
 * True once the server's re-check window (`AuthStatus.installWaitEndsAt`) has ended, or when
 * there is none.
 */
export function isInstallWaitOver(waitEndsAt: number | null, now: number): boolean {
  return waitEndsAt === null || now >= waitEndsAt;
}
