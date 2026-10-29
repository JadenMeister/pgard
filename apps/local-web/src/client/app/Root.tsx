import { useState } from "react";
import { App } from "./App";

/**
 * Remounts the app when the project changes (picker mode), so no scan, authorization or filter
 * state of the old project survives in the page. The legal notice is accepted once per page.
 */
export function Root() {
  const [generation, setGeneration] = useState(0);
  const [hasAcceptedNotice, setHasAcceptedNotice] = useState(false);
  return (
    <App
      key={generation}
      initialNoticeAccepted={hasAcceptedNotice}
      onNoticeAccepted={() => setHasAcceptedNotice(true)}
      onProjectChanged={() => setGeneration((current) => current + 1)}
    />
  );
}
