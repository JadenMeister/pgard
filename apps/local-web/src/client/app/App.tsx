import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { RuleTextsResponse, SessionInfo, TargetInfo } from "../../shared/api-types";
import { apiGet, hasSessionToken } from "../api/client";
import { loadWithRetry } from "../api/retry";
import { DeviceCodeNotice } from "../components/github/DeviceCodeNotice";
import { EmptyState } from "../components/ui/EmptyState";
import { Notice } from "../components/ui/Notice";
import { Section } from "../components/ui/Section";
import { LanguageToggle, useI18n } from "../i18n/I18nProvider";
import { buildFindingsView, EMPTY_FILTERS } from "../features/findings/filter-findings";
import { FindingsDashboard } from "../features/findings/FindingsDashboard";
import { ResultOverview } from "../features/findings/ResultOverview";
import { LegalNotice } from "../features/legal/LegalNotice";
import {
  AUTHORIZATION_SECTION_ID,
  AuthorizationSection,
} from "../features/onboarding/AuthorizationSection";
import { SessionActions } from "../features/onboarding/SessionActions";
import { useAuthorization } from "../features/onboarding/use-authorization";
import { ReportPanel } from "../features/reports/ReportPanel";
import { CoverageView } from "../features/scan/CoverageView";
import { ScanProgress } from "../features/scan/ScanProgress";
import { ScanStrip } from "../features/scan/ScanStrip";
import { useScan } from "../features/scan/use-scan";
import { RuleStatsPanel } from "../features/standards/RuleStatsPanel";
import { StandardsCoveragePanel } from "../features/standards/StandardsCoveragePanel";
import { TargetPanel } from "../features/target/TargetPanel";
import { targetRefreshKey } from "../features/target/target-refresh";
import { useFilterState } from "./use-filter-state";
import { useHashView, VIEWS, type View } from "./views";

export function App() {
  const [session, setSession] = useState<SessionInfo | null>(null);
  const { m, language } = useI18n();
  const [error, setError] = useState<"token" | "session" | null>(null);
  const [hasAcceptedNotice, setHasAcceptedNotice] = useState(false);
  const [target, setTarget] = useState<TargetInfo | null>(null);
  const [ruleTexts, setRuleTexts] = useState<RuleTextsResponse | null>(null);
  const [ruleTextsFailed, setRuleTextsFailed] = useState(false);
  const isReady = session !== null && hasAcceptedNotice;
  const authorization = useAuthorization(isReady);
  const auth = authorization.status;
  const control = useScan();
  const scan = control.scan;
  const result = scan?.result ?? null;
  const hasResult = result !== null;
  const [view, setView] = useHashView();
  const mainRef = useRef<HTMLElement>(null);
  // Focus requests after a view change made from the nav or the strip: the view's region, or a
  // named section in it. Each request focuses once.
  const [focusRequest, setFocusRequest] = useState<{ id: string | null; count: number }>({
    id: null,
    count: 0,
  });

  useEffect(() => {
    if (focusRequest.count === 0) return;
    const element =
      focusRequest.id === null ? mainRef.current : document.getElementById(focusRequest.id);
    element?.focus();
    element?.scrollIntoView({ block: "start" });
  }, [focusRequest]);

  const goTo = (next: View, sectionId: string | null = null): void => {
    setView(next);
    setFocusRequest((current) => ({ id: sectionId, count: current.count + 1 }));
  };

  // One filter state for the Overview panels and the Findings table, kept in the address
  // (`#findings?severity=high`) so reload, back and forward restore it.
  const [filters, setFilters, clearFilters] = useFilterState();

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

  // The confirmed target: read at start, and again whenever the authorization changes (a check
  // finished, either sign-out, another account), because the server may have cleared it. A stale
  // "Confirmed target" would otherwise hide the "no web target" guidance of the scan strip.
  const targetKey = targetRefreshKey(auth);
  useEffect(() => {
    if (!hasSessionToken()) return undefined;
    let isCurrent = true;
    apiGet<TargetInfo | null>("/api/target")
      .then((next) => {
        if (isCurrent) setTarget(next);
      })
      .catch(() => {
        if (isCurrent && targetKey !== null) setTarget(null);
      });
    return () => {
      isCurrent = false;
    };
  }, [targetKey]);

  useEffect(() => {
    if (!hasSessionToken()) {
      setError("token");
      return;
    }
    apiGet<SessionInfo>("/api/session")
      .then(setSession)
      .catch(() => setError("session"));
  }, []);

  const startScan = async (): Promise<void> => {
    setView("overview");
    await control.start();
  };

  const isStopped = scan?.status === "cancelled" || scan?.status === "failed";
  const noResult = (title: string): ReactNode => (
    <Section title={title}>
      <EmptyState title={control.isRunning ? m.scan.progress.title : m.overview.noScan} />
    </Section>
  );
  const blockedResult = (title: string): ReactNode => (
    <Section title={title}>
      <EmptyState title={m.findings.overall.blocked} />
    </Section>
  );

  const renderView = (): ReactNode => {
    if (session === null) return null;
    switch (view) {
      case "overview":
        return (
          <ResultOverview
            result={result}
            ruleTexts={ruleTexts}
            emptyText={control.isRunning ? null : m.overview.noScan}
            filters={filters}
            onFilter={setFilters}
            onClearFilters={clearFilters}
            onOpenFindings={() => goTo("findings")}
            onCoverage={() => goTo("coverage")}
            lead={
              <>
                {control.isRunning && scan !== null && (
                  <ScanProgress
                    scopes={scan.scopes}
                    events={scan.progress}
                    elapsedSeconds={control.elapsedSeconds}
                  />
                )}
                {control.isRunning && scan?.deviceCode && (
                  <DeviceCodeNotice deviceCode={scan.deviceCode} />
                )}
                {isStopped && scan !== null && scan.progress.length > 0 && (
                  <ScanProgress
                    scopes={scan.scopes}
                    events={scan.progress}
                    elapsedSeconds={0}
                    isStopped
                  />
                )}
                {scan?.message && (
                  <Notice tone={scan.status === "cancelled" ? "warning" : "error"}>
                    {scan.message}
                  </Notice>
                )}
              </>
            }
            aside={
              <>
                <AuthorizationSection session={session} authorization={authorization} />
                <TargetPanel
                  auth={auth}
                  presetPort={session.presetTargetPort}
                  target={target}
                  onTarget={setTarget}
                />
              </>
            }
          />
        );
      case "findings":
        return result === null ? (
          noResult(m.nav.findings)
        ) : (
          <FindingsDashboard
            result={result}
            ruleTexts={ruleTexts}
            linkedFilters={{ filters, onChange: setFilters, onClear: clearFilters }}
          />
        );
      case "coverage":
        return result === null || scan === null ? (
          noResult(m.nav.coverage)
        ) : (
          <CoverageView scan={scan} result={result} />
        );
      case "standards":
        if (result === null) return noResult(m.cards.standards);
        if (result.overallStatus === "blocked") return blockedResult(m.cards.standards);
        return <StandardsCoveragePanel result={result} />;
      case "rules":
        if (result === null || result.ruleStats === undefined) return noResult(m.cards.ruleStats);
        if (result.overallStatus === "blocked") return blockedResult(m.cards.ruleStats);
        return <RuleStatsPanel result={result} ruleTexts={ruleTexts} />;
      case "export":
        if (result === null) return noResult(m.cards.report);
        if (result.overallStatus === "blocked") return blockedResult(m.cards.report);
        return <ReportPanel />;
    }
  };

  // The same count as the Findings title: regular findings, without test, vendored, suppressed or
  // baseline ones.
  const findingCount = useMemo(
    () => (result === null ? null : buildFindingsView(result.findings, EMPTY_FILTERS).total),
    [result],
  );

  return (
    <>
      <a className="skip-link" href="#main">
        {m.app.skipToContent}
      </a>
      <header className="topbar">
        <div className="wrap topbar-in">
          <p className="brand">
            <span className="brand-name">pgard</span>
            <span className="brand-meta">{m.app.subtitle(session ? session.version : null)}</span>
          </p>
          <LanguageToggle />
        </div>
      </header>
      {isReady && (
        <>
          <ScanStrip
            projectName={session.projectName}
            authorization={authorization}
            control={{ ...control, start: startScan }}
            target={target}
            onShowAuthorization={() => goTo("overview", AUTHORIZATION_SECTION_ID)}
          />
          <div className="viewnav">
            <div className="wrap viewnav-in">
              <nav aria-label={m.nav.label}>
                <ul className="viewnav-list">
                  {VIEWS.map((entry) => (
                    <li key={entry}>
                      <a
                        href={`#${entry}`}
                        aria-current={entry === view ? "page" : undefined}
                        onClick={(event) => {
                          event.preventDefault();
                          goTo(entry);
                        }}
                      >
                        {m.nav[entry]}
                        {entry === "findings" && findingCount !== null && (
                          <span className="viewnav-count num">{findingCount}</span>
                        )}
                      </a>
                    </li>
                  ))}
                </ul>
              </nav>
              <SessionActions authorization={authorization} />
            </div>
          </div>
        </>
      )}
      <main id="main" ref={mainRef} className="wrap main" tabIndex={-1} lang={language}>
        {!isReady && <h1 className="page-title">{m.app.title}</h1>}
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
        {isReady && renderView()}
      </main>
      <footer className="page-footer">
        <div className="wrap">{m.app.footer}</div>
      </footer>
    </>
  );
}
