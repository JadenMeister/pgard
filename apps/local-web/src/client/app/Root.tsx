import { useEffect, useState } from "react";
import type { SessionInfo } from "../../shared/api-types";
import { apiGet, hasSessionToken } from "../api/client";
import { SimpleApp } from "../features/simple/SimpleApp";
import { App } from "./App";

/**
 * Remounts the app when the project changes (picker mode), so no scan, authorization or filter
 * state of the old project survives in the page. The legal notice is accepted once per page.
 * PROTOTYPE (#414): when the server serves the simple screen (`ui: "simple"`), that screen is
 * shown first and the full dashboard is one link away.
 */
export function Root() {
  const [generation, setGeneration] = useState(0);
  const [hasAcceptedNotice, setHasAcceptedNotice] = useState(false);
  const [ui, setUi] = useState<SessionInfo["ui"] | null>(null);
  const [isFullOpen, setIsFullOpen] = useState(false);
  useEffect(() => {
    if (!hasSessionToken()) {
      setUi("full");
      return;
    }
    apiGet<SessionInfo>("/api/session")
      .then((session) => setUi(session.ui === "simple" ? "simple" : "full"))
      .catch(() => setUi("full"));
  }, []);
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
