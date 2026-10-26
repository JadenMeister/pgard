import { useState } from "react";
import type { ScanScope } from "@pgard/findings";
import type { ScanStatus, TargetInfo } from "../../../shared/api-types";
import { apiGet, apiPost } from "../../api/client";
import { DeviceCodeNotice } from "../../components/github/DeviceCodeNotice";
import { Card, Notice } from "../../components/ui/Card";
import { usePolling } from "../../hooks/use-polling";
import { useI18n } from "../../i18n/I18nProvider";
import { ConfigNotices } from "./ConfigNotices";
import { CoverageTable } from "./CoverageTable";

const SCOPES: readonly ScanScope[] = ["code", "history", "web"];

interface ScanPanelProps {
  target: TargetInfo | null;
  scan: ScanStatus | null;
  onScan: (scan: ScanStatus) => void;
}

/** Starts a scan through the local server (scan-core, gate included) and shows progress. */
export function ScanPanel({ target, scan, onScan }: ScanPanelProps) {
  const { m } = useI18n();
  const [scopes, setScopes] = useState<ScanScope[]>(["code", "history"]);
  const [error, setError] = useState<string | null>(null);
  const isRunning = scan?.status === "running";

  usePolling(async () => onScan(await apiGet<ScanStatus>("/api/scan")), 1000, isRunning);

  const toggle = (scope: ScanScope): void => {
    setScopes((current) =>
      current.includes(scope) ? current.filter((entry) => entry !== scope) : [...current, scope],
    );
  };

  const start = async (): Promise<void> => {
    setError(null);
    try {
      onScan(await apiPost<ScanStatus>("/api/scan", { scopes }));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : m.common.requestFailed);
    }
  };

  const cancel = async (): Promise<void> => {
    onScan(await apiPost<ScanStatus>("/api/scan/cancel"));
  };

  return (
    <Card title={m.cards.scan} step={3}>
      <fieldset className="scopes" disabled={isRunning}>
        <legend>{m.scan.scope}</legend>
        {SCOPES.map((scope) => (
          <label key={scope} className="scope">
            <input
              type="checkbox"
              checked={scopes.includes(scope)}
              onChange={() => toggle(scope)}
            />
            <span>
              {m.scan.scopes[scope].label}{" "}
              <span className="muted">- {m.scan.scopes[scope].hint}</span>
            </span>
          </label>
        ))}
      </fieldset>
      {scopes.includes("web") && target === null && (
        <Notice tone="warning">{m.scan.noWebTarget}</Notice>
      )}
      <div className="button-row">
        <button
          type="button"
          className="button primary"
          disabled={isRunning || scopes.length === 0}
          onClick={() => void start()}
        >
          {m.scan.run}
        </button>
        {isRunning && (
          <button type="button" className="button" onClick={() => void cancel()}>
            {m.scan.cancel}
          </button>
        )}
      </div>
      {isRunning && scan?.deviceCode && <DeviceCodeNotice deviceCode={scan.deviceCode} />}
      {scan !== null && scan.progress.length > 0 && (
        <ol className="progress" aria-live="polite">
          {scan.progress.slice(-8).map((event, index) => (
            <li key={`${index}-${event.stage}-${event.status}`}>
              <strong>{event.stage}</strong> {event.status}
              {event.message ? ` - ${event.message}` : ""}
            </li>
          ))}
        </ol>
      )}
      {scan?.message && (
        <Notice tone={scan.status === "cancelled" ? "warning" : "error"}>{scan.message}</Notice>
      )}
      {scan?.result && <ConfigNotices coverage={scan.result.coverage} />}
      {scan?.result && <CoverageTable coverage={scan.result.coverage} />}
      {error && <Notice tone="error">{error}</Notice>}
    </Card>
  );
}
