import type { InstallRemedyDto, OwnerApprovalRecheckDto } from "../../../shared/api-types";
import { isGitHubUrl } from "../../components/github/device-code";

/**
 * Same timing as the CLI: re-check every 5 s, for up to 10 minutes. The server enforces both (at
 * most one re-check per 5 s, only within 10 minutes of the check that offered the install).
 */
export const INSTALL_POLL_INTERVAL_MS = 5_000;

export const INSTALL_BUTTON_LABEL = "Install the PGARD GitHub App";
export const WAITING_FOR_INSTALL_TEXT =
  "Waiting for the PGARD GitHub App to be installed... PGARD checks every 5 seconds and runs the full authorization again once it is installed.";
export const INSTALL_WAIT_TIMED_OUT_TEXT =
  "Stopped waiting for the PGARD GitHub App installation after 10 minutes. Install it, then check again.";
export const REPOSITORY_ACCESS_BUTTON_LABEL = "Open the App's repository access";
export const WAITING_FOR_REPOSITORY_ACCESS_TEXT =
  "Waiting for the repository to be added to the PGARD GitHub App's repository access... PGARD checks every 5 seconds and runs the full authorization again once it is added.";
export const REPOSITORY_ACCESS_WAIT_TIMED_OUT_TEXT =
  "Stopped waiting for the repository to be added to the PGARD GitHub App's repository access after 10 minutes. Add it, then check again.";

/** The button and waiting texts for a remedy: an install, or adding a repository to one. */
export function installTexts(remedy: InstallRemedyDto): {
  button: string;
  waiting: string;
  timedOut: string;
} {
  return remedy.missing === "repository_access"
    ? {
        button: REPOSITORY_ACCESS_BUTTON_LABEL,
        waiting: WAITING_FOR_REPOSITORY_ACCESS_TEXT,
        timedOut: REPOSITORY_ACCESS_WAIT_TIMED_OUT_TEXT,
      }
    : {
        button: INSTALL_BUTTON_LABEL,
        waiting: WAITING_FOR_INSTALL_TEXT,
        timedOut: INSTALL_WAIT_TIMED_OUT_TEXT,
      };
}

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
): InstallRemedyView {
  const account = remedy.account.login;
  const target = repo ?? "this repository";
  if (remedy.url === null || !isGitHubUrl(remedy.url)) {
    return {
      kind: "unavailable",
      text: remedy.unavailableReason ?? "No install link is available.",
    };
  }
  if (remedy.canApprove === "no" && remedy.missing === "repository_access") {
    return {
      kind: "ask_owner",
      url: remedy.url,
      text: `Ask an owner of ${account} to add ${target} to the PGARD GitHub App's repository access:`,
    };
  }
  if (remedy.canApprove === "no") {
    return {
      kind: "ask_owner",
      url: remedy.url,
      text: `Ask an owner of ${account} to install the PGARD GitHub App:`,
    };
  }
  if (remedy.missing === "repository_access") {
    const lead = `GitHub shows no access to ${target}. The PGARD GitHub App is already installed on ${account}, but its repository access does not include this repository (or your account has no access to it).`;
    const steps = `On GitHub, under "Repository access", choose "Only select repositories", add ${target}, then click Save. Changing the App's repository access is the owner approval; PGARD cannot change it for you.`;
    return {
      kind: "install",
      url: remedy.url,
      text:
        remedy.canApprove === "yes"
          ? `${lead} Owner approval: add ${target} to the PGARD GitHub App's repository access. ${steps}`
          : `${lead} If you are an owner of ${account}, add ${target} to the PGARD GitHub App's repository access on its settings page; otherwise ask an owner to do it there: ${remedy.url} ${steps}`,
    };
  }
  if (remedy.missing === "access") {
    return {
      kind: "install",
      url: remedy.url,
      text: `GitHub shows no access to this repository. If it is private, the PGARD GitHub App must be installed for it; PGARD cannot tell this from missing account access. If you are an owner of ${account}, install the App on the install page; otherwise ask an owner to install it there: ${remedy.url} The page pre-selects "All repositories"; to limit PGARD to this repository, choose "Only select repositories" and pick ${target}, then click Install.`,
    };
  }
  if (remedy.canApprove === "unknown") {
    // Same wording as the CLI: GitHub would not show the membership before the App is installed.
    return {
      kind: "install",
      url: remedy.url,
      text: `If you are an owner of ${account}, install the App on the install page; otherwise ask an owner to install it there: ${remedy.url}`,
    };
  }
  return {
    kind: "install",
    url: remedy.url,
    text: `Owner approval: install the PGARD GitHub App on ${account}. On GitHub, choose "Only select repositories" (this repository) or "All repositories", then click Install. Installing the App is the owner approval; PGARD cannot install it for you.`,
  };
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
