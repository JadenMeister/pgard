import { useEffect, useState } from "react";
import type { InstallRemedyDto, OwnerApprovalRecheckDto } from "../../../shared/api-types";
import { apiPost, ApiRequestError } from "../../api/client";
import { Notice } from "../../components/ui/Card";
import { usePolling } from "../../hooks/use-polling";
import {
  describeInstallRemedy,
  INSTALL_POLL_INTERVAL_MS,
  installTexts,
  isInstallWaitOver,
  nextInstallStep,
} from "./install-remedy";

interface InstallAppNoticeProps {
  remedy: InstallRemedyDto;
  /** `owner/name` of the checked repository, for the wording. */
  repo?: string | null;
  /**
   * When the server stops accepting re-checks (`AuthStatus.installWaitEndsAt`). It comes from the
   * server, so a remount (for example after a transient error) never restarts the 10 minutes.
   */
  waitEndsAt: number | null;
  /** Runs the full authorization again (`POST /api/auth/verify`). */
  onInstalled: () => void;
}

/**
 * Shown when the latest check is blocked only because the PGARD GitHub App is not installed for
 * this repository. A user who can install it gets a button (new tab) and the panel re-checks
 * owner approval every 5 s until the server's 10-minute window ends, then starts the full check
 * again.
 */
export function InstallAppNotice({
  remedy,
  repo = null,
  waitEndsAt,
  onInstalled,
}: InstallAppNoticeProps) {
  const view = describeInstallRemedy(remedy, repo);
  const texts = installTexts(remedy);
  const canWait = view.kind === "install" && !isInstallWaitOver(waitEndsAt, Date.now());
  const [isWaiting, setIsWaiting] = useState(canWait);
  const [isTimedOut, setIsTimedOut] = useState(view.kind === "install" && !canWait);

  useEffect(() => {
    const isOver = isInstallWaitOver(waitEndsAt, Date.now());
    setIsWaiting(view.kind === "install" && !isOver);
    setIsTimedOut(view.kind === "install" && isOver);
  }, [view.kind, remedy.url, waitEndsAt]);

  const stopWaiting = (): void => {
    setIsWaiting(false);
    setIsTimedOut(true);
  };

  usePolling(
    async () => {
      if (isInstallWaitOver(waitEndsAt, Date.now())) {
        stopWaiting();
        return;
      }
      let recheck: OwnerApprovalRecheckDto;
      try {
        recheck = await apiPost<OwnerApprovalRecheckDto>("/api/auth/owner-approval");
      } catch (error) {
        // The server's window is the one that counts; anything else is retried on the next tick.
        if (error instanceof ApiRequestError && error.code === "install_wait_expired") {
          stopWaiting();
        }
        return;
      }
      if (nextInstallStep(recheck) === "reverify") {
        setIsWaiting(false);
        onInstalled();
      }
    },
    INSTALL_POLL_INTERVAL_MS,
    isWaiting,
  );

  if (view.kind === "unavailable") return <Notice tone="warning">{view.text}</Notice>;
  if (view.kind === "ask_owner") {
    return (
      <Notice tone="warning">
        {view.text}{" "}
        <a href={view.url} target="_blank" rel="noreferrer noopener">
          {view.url}
        </a>
      </Notice>
    );
  }
  return (
    <div className="device-code" role="status">
      <p>{view.text}</p>
      <p>
        <a className="button primary" href={view.url} target="_blank" rel="noreferrer noopener">
          {texts.button}
        </a>
      </p>
      {isWaiting && <p className="muted">{texts.waiting}</p>}
      {isTimedOut && <p className="muted">{texts.timedOut}</p>}
    </div>
  );
}
