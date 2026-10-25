import { useEffect, useRef, useState } from "react";
import type { InstallRemedyDto, OwnerApprovalRecheckDto } from "../../../shared/api-types";
import { apiPost } from "../../api/client";
import { Notice } from "../../components/ui/Card";
import { usePolling } from "../../hooks/use-polling";
import {
  describeInstallRemedy,
  INSTALL_BUTTON_LABEL,
  INSTALL_POLL_INTERVAL_MS,
  INSTALL_WAIT_LIMIT_MS,
  INSTALL_WAIT_TIMED_OUT_TEXT,
  nextInstallStep,
  WAITING_FOR_INSTALL_TEXT,
} from "./install-remedy";

interface InstallAppNoticeProps {
  remedy: InstallRemedyDto;
  /** Runs the full authorization again (`POST /api/auth/verify`). */
  onInstalled: () => void;
}

/**
 * Shown when the latest check is blocked only because the PGARD GitHub App is not installed for
 * this repository. A user who can install it gets a button (new tab) and the panel re-checks
 * owner approval every 5 s for up to 10 minutes, then starts the full check again.
 */
export function InstallAppNotice({ remedy, onInstalled }: InstallAppNoticeProps) {
  const view = describeInstallRemedy(remedy);
  const startedAt = useRef(Date.now());
  const [isWaiting, setIsWaiting] = useState(view.kind === "install");
  const [isTimedOut, setIsTimedOut] = useState(false);

  useEffect(() => {
    startedAt.current = Date.now();
    setIsWaiting(view.kind === "install");
    setIsTimedOut(false);
  }, [view.kind, remedy.url]);

  usePolling(
    async () => {
      if (Date.now() - startedAt.current >= INSTALL_WAIT_LIMIT_MS) {
        setIsWaiting(false);
        setIsTimedOut(true);
        return;
      }
      const recheck = await apiPost<OwnerApprovalRecheckDto>("/api/auth/owner-approval");
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
          {INSTALL_BUTTON_LABEL}
        </a>
      </p>
      {isWaiting && <p className="muted">{WAITING_FOR_INSTALL_TEXT}</p>}
      {isTimedOut && <p className="muted">{INSTALL_WAIT_TIMED_OUT_TEXT}</p>}
    </div>
  );
}
