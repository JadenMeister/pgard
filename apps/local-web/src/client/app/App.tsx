import { useEffect, useState } from "react";
import type { AuthStatus, ScanStatus, SessionInfo, TargetInfo } from "../../shared/api-types";
import { apiGet, hasSessionToken } from "../api/client";
import { Notice } from "../components/ui/Card";
import { FindingsDashboard } from "../features/findings/FindingsDashboard";
import { LegalNotice } from "../features/legal/LegalNotice";
import { AuthorizationPanel } from "../features/onboarding/AuthorizationPanel";
import { ReportPanel } from "../features/reports/ReportPanel";
import { ScanPanel } from "../features/scan/ScanPanel";
import { TargetPanel } from "../features/target/TargetPanel";

export function App() {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [hasAcceptedNotice, setHasAcceptedNotice] = useState(false);
  const [, setAuth] = useState<AuthStatus | null>(null);
  const [target, setTarget] = useState<TargetInfo | null>(null);
  const [scan, setScan] = useState<ScanStatus | null>(null);

  useEffect(() => {
    if (!hasSessionToken()) {
      setError(
        "This page needs the private session URL printed by `pgard dashboard`. Open that URL again.",
      );
      return;
    }
    apiGet<TargetInfo | null>("/api/target")
      .then(setTarget)
      .catch(() => undefined);
    apiGet<SessionInfo>("/api/session")
      .then(setSession)
      .catch(() => setError("The dashboard session is not available. Restart `pgard dashboard`."));
  }, []);

  return (
    <div className="page">
      <header className="page-header">
        <h1>PGARD</h1>
        <p className="muted">Local security dashboard {session ? `- v${session.version}` : ""}</p>
      </header>
      <main>
        {error && <Notice tone="error">{error}</Notice>}
        {session !== null && !hasAcceptedNotice && (
          <LegalNotice onAccept={() => setHasAcceptedNotice(true)} />
        )}
        {session !== null && hasAcceptedNotice && (
          <>
            <AuthorizationPanel session={session} onStatus={setAuth} />
            <TargetPanel
              presetPort={session.presetTargetPort}
              target={target}
              onTarget={setTarget}
            />
            <ScanPanel target={target} scan={scan} onScan={setScan} />
            {scan?.result && <FindingsDashboard result={scan.result} />}
            {scan?.result && scan.result.overallStatus !== "blocked" && <ReportPanel />}
          </>
        )}
      </main>
      <footer className="page-footer muted small">
        Runs on 127.0.0.1 only. Results and sign-in are discarded when the dashboard stops.
      </footer>
    </div>
  );
}
