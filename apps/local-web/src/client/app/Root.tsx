import { useEffect, useState } from "react";
import type { SessionInfo } from "../../shared/api-types";
import { apiGet, connectSession, setSessionEndedListener } from "../api/client";
import { SimpleApp } from "../features/simple/SimpleApp";
import { App } from "./App";
import { ConnectionNotice, type NoticeOutcome } from "./ConnectionNotice";

/**
 * Remounts the app when the project changes (picker mode), so no scan, authorization or filter
 * state of the old project survives in the page. The legal notice is accepted once per page.
 * When the server serves the simple screen (`ui: "simple"`, `pgard web`), that screen is shown
 * first and the full dashboard is one link away under "More".
 *
 * Before anything else the tab connects (#419): it spends the link's one-time token, or reuses
 * this tab's session after a reload. A reused or expired link, or an ended session, shows a
 * plain page saying what to do instead of the app.
 */
export function Root() {
  const [generation, setGeneration] = useState(0);
  const [hasAcceptedNotice, setHasAcceptedNotice] = useState(false);
  const [ui, setUi] = useState<SessionInfo["ui"] | null>(null);
  const [isFullOpen, setIsFullOpen] = useState(false);
  const [notice, setNotice] = useState<NoticeOutcome | null>(null);
  useEffect(() => {
    let isCurrent = true;
    setSessionEndedListener(() => setNotice("ended"));
    void connectSession().then((outcome) => {
      if (!isCurrent) return;
      if (outcome !== "connected") {
        setNotice(outcome);
        return;
      }
      apiGet<SessionInfo>("/api/session")
        .then((session) => {
          if (isCurrent) setUi(session.ui === "simple" ? "simple" : "full");
        })
        .catch(() => {
          if (isCurrent) setUi("full");
        });
    });
    return () => {
      isCurrent = false;
      setSessionEndedListener(null);
    };
  }, []);
  if (notice !== null) return <ConnectionNotice outcome={notice} />;
  if (ui === null) return null;
  const remount = (): void => setGeneration((current) => current + 1);
  if (ui === "simple" && !isFullOpen) {
    return (
      <SimpleApp
        key={generation}
        initialNoticeAccepted={hasAcceptedNotice}
        onNoticeAccepted={() => setHasAcceptedNotice(true)}
        onProjectChanged={remount}
        onOpenFull={() => setIsFullOpen(true)}
      />
    );
  }
  return (
    <App
      key={generation}
      initialNoticeAccepted={hasAcceptedNotice}
      onNoticeAccepted={() => setHasAcceptedNotice(true)}
      onProjectChanged={remount}
    />
  );
}
