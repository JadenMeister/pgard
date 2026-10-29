import { useEffect, useMemo, useState, type ReactNode } from "react";
import type { Severity } from "@pgard/findings";
import type { RuleTextsResponse, ScanStatus, SessionInfo } from "../../../shared/api-types";
import type { PickerBrowseResponse, PickerPathResponse } from "../../../shared/picker-types";
import { apiGet, apiPost, getProjectEpoch, setProjectEpoch } from "../../api/client";
import { loadWithRetry } from "../../api/retry";
import { SeverityBar } from "../../components/charts/SeverityBar";
import { Button } from "../../components/ui/Button";
import { Notice } from "../../components/ui/Notice";
import { usePolling } from "../../hooks/use-polling";
import { LanguageToggle, useI18n } from "../../i18n/I18nProvider";
import { buildFindingsView, EMPTY_FILTERS } from "../findings/filter-findings";
import { FindingTable } from "../findings/FindingTable";
import { LegalNotice } from "../legal/LegalNotice";
import { BlockedNote } from "../picker/CandidateCard";
import { pickerErrorText } from "../picker/error-text";
import { usePicker, type PickerControl } from "../picker/use-picker";
import { useElapsedSeconds } from "../scan/ScanProgress";
import { CoverageView } from "../scan/CoverageView";
import { RuleStatsPanel } from "../standards/RuleStatsPanel";
import { StandardsCoveragePanel } from "../standards/StandardsCoveragePanel";
import { simpleText, type SimpleText } from "./simple-text";

type FolderRefusal = NonNullable<PickerBrowseResponse["refusal"]>;

/**
 * PROTOTYPE (#414): the one-screen flow of `pgard web` (`PGARD_WEB_PROTOTYPE=code-only`).
 * Choose a folder, press Scan, read the findings. The scan is code-only: the server runs no
 * authorization gate, reads the current files only and stores nothing, so every result carries
 * the "not authorized" label. Standards, rules, coverage, trend and export sit under More; the
 * full dashboard (GitHub sign-in, Git history, web checks) is one optional link away.
 */
export interface SimpleAppProps {
  initialNoticeAccepted: boolean;
  onNoticeAccepted: () => void;
  /** The project was confirmed or cleared: remount with fresh state. */
  onProjectChanged: () => void;
  onOpenFull: () => void;
}

type MorePanel = "coverage" | "standards" | "rules";

function Steps({ t }: { t: SimpleText }) {
  return (
    <ol className="simple-steps">
      {t.steps.map((step, index) => (
        <li key={step}>
          <span className="simple-step-num num" aria-hidden="true">
            {index + 1}
          </span>
          {step}
        </li>
      ))}
    </ol>
  );
}

/** The refusal of a chosen or pasted folder, in the page language, with its fix. */
function Refusal({ refusal, t }: { refusal: FolderRefusal; t: SimpleText }) {
  const text = t.refusals[refusal.code];
  return (
    <div className="pick-blocked simple-refusal" role="alert">
      <p className="pick-blocked-title">{text.reason}</p>
      <p>{text.fix}</p>
      {refusal.paths.length > 0 && (
        <ul className="pick-paths">
          {refusal.paths.map((entry) => (
            <li key={entry}>
              <code>{entry}</code>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * Step 1 without a project: the OS folder dialog ("Choose folder") or a pasted path. The server
 * opens the dialog and checks the folder; the page only shows the result and asks to confirm.
 */
function FolderStep({ control, t }: { control: PickerControl; t: SimpleText }) {
  const { language } = useI18n();
  const { candidate } = control;
  const [dialog, setDialog] = useState<PickerBrowseResponse["status"]>("idle");
  const [refusal, setRefusal] = useState<FolderRefusal | null>(null);
  const [pasted, setPasted] = useState("");
  const [isChecking, setIsChecking] = useState(false);
  const [requestError, setRequestError] = useState<string | null>(null);

  const apply = (response: PickerBrowseResponse | PickerPathResponse): void => {
    setRefusal(response.refusal);
    if (response.candidate !== null) control.choose(response.candidate);
  };
  usePolling(
    async () => {
      const response = await apiGet<PickerBrowseResponse>("/api/picker/browse");
      setDialog(response.status);
      if (response.status !== "open") apply(response);
    },
    700,
    dialog === "open",
  );

  const openDialog = (): void => {
    setRequestError(null);
    setRefusal(null);
    apiPost<PickerBrowseResponse>("/api/picker/browse", { lang: language })
      .then((response) => {
        setDialog(response.status);
        if (response.status !== "open") apply(response);
      })
      .catch((caught: unknown) =>
        setRequestError(caught instanceof Error ? caught.message : t.requestFailed),
      );
  };
  const cancelDialog = (): void => {
    apiPost<PickerBrowseResponse>("/api/picker/browse/cancel", {})
      .then((response) => setDialog(response.status))
      .catch(() => undefined);
  };
  const submitPasted = (): void => {
    if (pasted.trim() === "" || isChecking) return;
    setRequestError(null);
    setRefusal(null);
    setIsChecking(true);
    apiPost<PickerPathResponse>("/api/picker/path", { path: pasted })
      .then(apply)
      .catch((caught: unknown) =>
        setRequestError(caught instanceof Error ? caught.message : t.requestFailed),
      )
      .finally(() => setIsChecking(false));
  };

  if (candidate !== null) {
    return (
      <div className="simple-confirm">
        <p>{t.candidateConfirm}</p>
        <pre className="pick-confirm-path">{candidate.displayPath}</pre>
        {candidate.remote.status === "github" && candidate.codeOnly === undefined && (
          <p className="muted small">{t.githubRepo(candidate.remote.repo)}</p>
        )}
        {candidate.codeOnly !== undefined && (
          <p className="muted small">{t.codeOnlyReason[candidate.codeOnly]}</p>
        )}
        {!candidate.selectable && (
          <BlockedNote candidate={candidate} addCommand={null} onRemoveRecent={null} />
        )}
        <p className="button-row">
          {candidate.selectable && (
            <Button variant="primary" disabled={control.isConfirming} onClick={control.confirm}>
              {control.isConfirming ? t.using : t.useFolder}
            </Button>
          )}
          <Button disabled={control.isConfirming} onClick={control.back}>
            {t.back}
          </Button>
        </p>
      </div>
    );
  }
  return (
    <>
      <p className="muted">{t.folderHint}</p>
      <p className="button-row">
        <button
          type="button"
          className="btn btn-primary simple-choose-button"
          disabled={dialog === "open"}
          onClick={openDialog}
        >
          {dialog === "open" ? t.dialogOpen : t.chooseFolder}
        </button>
        {dialog === "open" && (
          <Button size="sm" onClick={cancelDialog}>
            {t.cancel}
          </Button>
        )}
      </p>
      {dialog === "unavailable" && <Notice tone="warning">{t.dialogUnavailable}</Notice>}
      {dialog === "timeout" && <p className="muted small">{t.dialogTimeout}</p>}
      {dialog === "cancelled" && <p className="muted small">{t.dialogCancelled}</p>}
      <form
        className="simple-paste"
        onSubmit={(event) => {
          event.preventDefault();
          submitPasted();
        }}
      >
        <label htmlFor="simple-path" className="simple-paste-label">
          {t.pasteLabel}
        </label>
        <div className="simple-paste-row">
          <input
            id="simple-path"
            className="pick-input simple-path-input"
            type="text"
            autoComplete="off"
            spellCheck={false}
            maxLength={4096}
            placeholder={t.pastePlaceholder}
            value={pasted}
            onChange={(event) => setPasted(event.target.value)}
          />
          <Button type="submit" disabled={isChecking || pasted.trim() === ""}>
            {isChecking ? t.checking : t.pasteSubmit}
          </Button>
        </div>
      </form>
      {refusal !== null && <Refusal refusal={refusal} t={t} />}
      {requestError !== null && <Notice tone="error">{requestError}</Notice>}
    </>
  );
}

function NotAuthorizedLabel({ t, onConnect }: { t: SimpleText; onConnect: () => void }) {
  return (
    <div className="simple-noauth" role="note">
      <p className="simple-noauth-head">
        <span className="badge badge-partial simple-noauth-badge">{t.badge}</span>
        <strong>{t.badgeTitle}</strong>
      </p>
      <p className="muted">{t.badgeBody}</p>
      <p>
        <button type="button" className="link-button" onClick={onConnect}>
          {t.connect}
        </button>
        <span className="muted small"> {t.connectHint}</span>
      </p>
    </div>
  );
}

export function SimpleApp({
  initialNoticeAccepted,
  onNoticeAccepted,
  onProjectChanged,
  onOpenFull,
}: SimpleAppProps) {
  const { m, language } = useI18n();
  const t = simpleText(language);
  const [session, setSession] = useState<SessionInfo | null>(null);
  const [sessionError, setSessionError] = useState(false);
  const [hasAcceptedNotice, setHasAcceptedNotice] = useState(initialNoticeAccepted);
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [ruleTexts, setRuleTexts] = useState<RuleTextsResponse | null>(null);
  const [severity, setSeverity] = useState<Severity | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [isMoreOpen, setIsMoreOpen] = useState(false);
  const [morePanel, setMorePanel] = useState<MorePanel>("coverage");
  const [changeError, setChangeError] = useState<string | null>(null);
  const picker = usePicker(() => onProjectChanged());

  useEffect(() => {
    apiGet<SessionInfo>("/api/session")
      .then((next) => {
        // Every state-changing picker and scan call carries this epoch.
        setProjectEpoch(next.projectEpoch);
        setSession(next);
      })
      .catch(() => setSessionError(true));
    // The scan of this page, if one ran before a reload.
    apiGet<ScanStatus>("/api/scan")
      .then((status) => (status.codeOnly ? setScan(status) : undefined))
      .catch(() => undefined);
  }, []);

  const isRunning = scan?.status === "running";
  const elapsed = useElapsedSeconds(isRunning);
  usePolling(async () => setScan(await apiGet<ScanStatus>("/api/scan")), 1000, isRunning);

  const result = scan?.status === "done" ? scan.result : null;
  useEffect(() => {
    if (result === null || ruleTexts !== null) return;
    return loadWithRetry(
      () => apiGet<RuleTextsResponse>("/api/rule-texts"),
      setRuleTexts,
      () => undefined,
    );
  }, [result, ruleTexts]);

  const view = useMemo(
    () =>
      result === null
        ? null
        : buildFindingsView(result.findings, { ...EMPTY_FILTERS, severity }, m),
    [result, severity, m],
  );
  const allCounts = useMemo(
    () => (result === null ? null : buildFindingsView(result.findings, EMPTY_FILTERS, m).counts),
    [result, m],
  );

  const project = session?.project ?? null;
  const isReady = session !== null && hasAcceptedNotice;

  const startScan = async (): Promise<void> => {
    setScanError(null);
    setSeverity(null);
    setPage(1);
    try {
      setScan(await apiPost<ScanStatus>("/api/code-scan", { epoch: getProjectEpoch() }));
    } catch (caught) {
      setScanError(caught instanceof Error ? caught.message : m.common.requestFailed);
    }
  };
  const cancelScan = async (): Promise<void> => {
    setScan(await apiPost<ScanStatus>("/api/scan/cancel"));
  };
  const changeFolder = (): void => {
    setChangeError(null);
    apiPost("/api/picker/clear", { epoch: getProjectEpoch() })
      .then(() => onProjectChanged())
      .catch((caught: unknown) => setChangeError(pickerErrorText(m, caught)));
  };

  const isPartial = result !== null && result.overallStatus !== "completed";
  const hasContextNote = view !== null && view.contextNote !== "";

  const renderMore = (): ReactNode => {
    if (result === null || scan === null) return <p className="muted">{t.moreNeedsScan}</p>;
    switch (morePanel) {
      case "coverage":
        return <CoverageView scan={scan} result={result} />;
      case "standards":
        return <StandardsCoveragePanel result={result} />;
      case "rules":
        return <RuleStatsPanel result={result} ruleTexts={ruleTexts} />;
    }
  };

  return (
    <>
      <a className="skip-link" href="#main">
        {m.app.skipToContent}
      </a>
      <header className="topbar">
        <div className="wrap topbar-in">
          <p className="brand">
            <span className="brand-name">pgard</span>
            <span className="badge badge-informational simple-proto">{t.prototypeTag}</span>
          </p>
          <LanguageToggle />
        </div>
      </header>
      <main id="main" className="wrap main simple" tabIndex={-1} lang={language}>
        <h1 className="page-title">{t.title}</h1>
        <p className="simple-lead">{t.lead}</p>
        <Steps t={t} />
        {sessionError && <Notice tone="error">{m.app.errorSession}</Notice>}
        {session !== null && !hasAcceptedNotice && (
          <LegalNotice
            onAccept={() => {
              setHasAcceptedNotice(true);
              onNoticeAccepted();
            }}
          />
        )}
        {isReady && (
          <>
            <section className="simple-card" aria-labelledby="simple-folder">
              <h2 id="simple-folder" className="simple-card-title">
                {t.folderTitle}
              </h2>
              {picker.error !== null && <Notice tone="error">{picker.error}</Notice>}
              {project === null ? (
                <FolderStep control={picker} t={t} />
              ) : (
                <div className="simple-chosen">
                  <p>
                    <span className="muted small">{t.chosenLabel}</span>{" "}
                    <strong>{project.name}</strong>
                    {project.repo !== null && <span className="pick-repo"> {project.repo}</span>}
                  </p>
                  <Button size="sm" disabled={isRunning} onClick={changeFolder}>
                    {t.change}
                  </Button>
                </div>
              )}
              {changeError !== null && <Notice tone="error">{changeError}</Notice>}
            </section>

            <section
              className={project === null ? "simple-card simple-card-off" : "simple-card"}
              aria-labelledby="simple-scan"
            >
              <h2 id="simple-scan" className="simple-card-title">
                {t.scanTitle}
              </h2>
              <p className="muted">{t.scanWhat}</p>
              <div className="simple-scan-row">
                {isRunning ? (
                  <>
                    <p className="pick-status" role="status">
                      <span className="pick-spinner" aria-hidden="true" />
                      {t.scanning(elapsed)}
                    </p>
                    <Button onClick={() => void cancelScan()}>{t.cancel}</Button>
                  </>
                ) : (
                  <button
                    type="button"
                    className="btn btn-primary simple-scan-button"
                    disabled={project === null}
                    onClick={() => void startScan()}
                  >
                    {result === null ? t.scanButton : t.rescanButton}
                  </button>
                )}
              </div>
              {scanError !== null && <Notice tone="error">{scanError}</Notice>}
              {scan?.status === "cancelled" && <Notice tone="warning">{t.cancelled}</Notice>}
              {scan?.status === "failed" && <Notice tone="error">{t.failed}</Notice>}
            </section>

            {result !== null && view !== null && allCounts !== null && (
              <section className="simple-card" aria-labelledby="simple-results">
                <div className="simple-results-head">
                  <h2 id="simple-results" className="simple-card-title">
                    {t.resultsTitle}
                  </h2>
                  <span className="simple-count num">{t.findingsCount(view.total)}</span>
                </div>
                <NotAuthorizedLabel t={t} onConnect={onOpenFull} />
                {isPartial && <Notice tone="warning">{t.partialNote}</Notice>}
                {view.total === 0 && severity === null ? (
                  <p className="empty-state-title">{t.noFindings}</p>
                ) : (
                  <>
                    <SeverityBar
                      counts={allCounts}
                      selected={severity}
                      onSelect={(next) => {
                        setSeverity(next);
                        setPage(1);
                      }}
                    />
                    <FindingTable
                      label={t.resultsTitle}
                      findings={view.visible}
                      ruleTexts={ruleTexts}
                      paging={{ page, pageSize, onPage: setPage, onPageSize: setPageSize }}
                    />
                  </>
                )}
                {hasContextNote && <p className="muted small">{t.extraNote}</p>}
              </section>
            )}

            <section className="simple-more" aria-labelledby="simple-more">
              <h2 id="simple-more" className="sr-only">
                {t.moreTitle}
              </h2>
              <button
                type="button"
                className="simple-more-toggle"
                aria-expanded={isMoreOpen}
                onClick={() => setIsMoreOpen((open) => !open)}
              >
                <span aria-hidden="true">{isMoreOpen ? "▾" : "▸"}</span> {t.moreTitle}
              </button>
              {isMoreOpen && (
                <div className="simple-more-body">
                  <p className="muted">{t.moreLead}</p>
                  <ul className="simple-more-list">
                    {(
                      [
                        ["coverage", t.moreCoverage],
                        ["standards", t.moreStandards],
                        ["rules", t.moreRules],
                      ] as const
                    ).map(([id, label]) => (
                      <li key={id}>
                        <button
                          type="button"
                          className="simple-more-item"
                          aria-pressed={morePanel === id}
                          onClick={() => setMorePanel(id)}
                        >
                          {label}
                        </button>
                      </li>
                    ))}
                    <li>
                      <span className="simple-more-item simple-more-off" aria-disabled="true">
                        {t.moreTrend}
                        <span className="muted small"> {t.moreTrendNote}</span>
                      </span>
                    </li>
                    <li>
                      <span className="simple-more-item simple-more-off" aria-disabled="true">
                        {t.moreExport}
                        <span className="muted small"> {t.moreExportNote}</span>
                      </span>
                    </li>
                    <li>
                      <button type="button" className="simple-more-item" onClick={onOpenFull}>
                        {t.moreFull}
                        <span className="muted small"> {t.moreFullNote}</span>
                      </button>
                    </li>
                  </ul>
                  <div className="simple-more-panel">{renderMore()}</div>
                </div>
              )}
            </section>
          </>
        )}
      </main>
      <footer className="page-footer">
        <div className="wrap">{m.app.footer}</div>
      </footer>
    </>
  );
}
