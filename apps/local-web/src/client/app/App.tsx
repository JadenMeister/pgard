import { useEffect, useState } from "react";
import type {
  AuthStatus,
  RuleTextsResponse,
  ScanStatus,
  SessionInfo,
  TargetInfo,
} from "../../shared/api-types";
import { apiGet, hasSessionToken } from "../api/client";
import { loadWithRetry } from "../api/retry";
import { Notice } from "../components/ui/Card";
import { LanguageToggle, useI18n } from "../i18n/I18nProvider";
import { FindingsDashboard } from "../features/findings/FindingsDashboard";
import { LegalNotice } from "../features/legal/LegalNotice";
import { AuthorizationPanel } from "../features/onboarding/AuthorizationPanel";
import { ReportPanel } from "../features/reports/ReportPanel";
import { ScanPanel } from "../features/scan/ScanPanel";
import { TargetPanel } from "../features/target/TargetPanel";

export function App() {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const { m, language } = useI18n();
  const [error, setError] = useState<"token" | "session" | null>(null);
  const [hasAcceptedNotice, setHasAcceptedNotice] = useState(false);
  const [auth, setAuth] = useState<AuthStatus | null>(null);
  const [target, setTarget] = useState<TargetInfo | null>(null);
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [ruleTexts, setRuleTexts] = useState<RuleTextsResponse | null>(null);
  const [ruleTextsFailed, setRuleTextsFailed] = useState(false);
  const hasResult = scan?.result != null;

  // Rule texts in both languages, fetched once when a result is first shown.
  useEffect(() => {
    if (!hasResult || ruleTexts !== null) return;
    // Up to three tries, then tell the person the texts stay in English.
    return loadWithRetry(
      () => apiGet<RuleTextsResponse>("/api/rule-texts"),
      setRuleTexts,
      () => setRuleTextsFailed(true),
    );
  }, [hasResult, ruleTexts]);

  useEffect(() => {
    if (!hasSessionToken()) {
      setError("token");
      return;
    }
    apiGet<TargetInfo | null>("/api/target")
      .then(setTarget)
      .catch(() => undefined);
    apiGet<SessionInfo>("/api/session")
      .then(setSession)
      .catch(() => setError("session"));
  }, []);

  return (
    <div className="page">
      <header className="page-header">
        <div className="page-title">
          <h1>PGARD</h1>
          <LanguageToggle />
        </div>
        <p className="muted">{m.app.subtitle(session ? session.version : null)}</p>
      </header>
      <main>
        {error && (
          <Notice tone="error">
            {error === "token" ? m.app.errorNoToken : m.app.errorSession}
          </Notice>
        )}
        {ruleTextsFailed && ruleTexts === null && language === "ko" && (
          <Notice tone="error">{m.app.errorRuleTexts}</Notice>
        )}
        {session !== null && !hasAcceptedNotice && (
          <LegalNotice onAccept={() => setHasAcceptedNotice(true)} />
        )}
        {session !== null && hasAcceptedNotice && (
          <>
            <AuthorizationPanel session={session} onStatus={setAuth} />
            <TargetPanel
              auth={auth}
              presetPort={session.presetTargetPort}
              target={target}
              onTarget={setTarget}
            />
            <ScanPanel target={target} scan={scan} onScan={setScan} />
            {scan?.result && <FindingsDashboard result={scan.result} ruleTexts={ruleTexts} />}
            {scan?.result && scan.result.overallStatus !== "blocked" && <ReportPanel />}
          </>
        )}
      </main>
      <footer className="page-footer muted small">{m.app.footer}</footer>
    </div>
  );
}
