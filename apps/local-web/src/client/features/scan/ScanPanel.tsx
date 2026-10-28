import { useState } from "react";
import type { ScanScope } from "@pgard/findings";
import type { ScanStatus, TargetInfo } from "../../../shared/api-types";
import { apiGet, apiPost } from "../../api/client";
import { DeviceCodeNotice } from "../../components/github/DeviceCodeNotice";
import { Button } from "../../components/ui/Button";
import { Card } from "../../components/ui/Card";
import { Notice } from "../../components/ui/Notice";
import { usePolling } from "../../hooks/use-polling";
import { useI18n } from "../../i18n/I18nProvider";
import { ConfigNotices } from "./ConfigNotices";
import { SuppressionNotices } from "./SuppressionNotices";
import { CoverageTable } from "./CoverageTable";
import { ActivityLog, ScanProgress, useElapsedSeconds } from "./ScanProgress";

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
  const elapsedSeconds = useElapsedSeconds(isRunning);

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
              <span className="scope-label">{m.scan.scopes[scope].label}</span>
              <span className="scope-hint">{m.scan.scopes[scope].hint}</span>
            </span>
          </label>
        ))}
      </fieldset>
      {scopes.includes("web") && target === null && (
        <Notice tone="warning">{m.scan.noWebTarget}</Notice>
      )}
      <div className="button-row">
        <Button
          variant="primary"
          disabled={isRunning || scopes.length === 0}
          onClick={() => void start()}
        >
          {m.scan.run}
        </Button>
        {isRunning && <Button onClick={() => void cancel()}>{m.scan.cancel}</Button>}
      </div>
      {isRunning && scan?.deviceCode && <DeviceCodeNotice deviceCode={scan.deviceCode} />}
      {isRunning && scan !== null && (
        <ScanProgress scopes={scan.scopes} events={scan.progress} elapsedSeconds={elapsedSeconds} />
      )}
      {!isRunning && scan !== null && <ActivityLog events={scan.progress} />}
      {scan?.message && (
        <Notice tone={scan.status === "cancelled" ? "warning" : "error"}>{scan.message}</Notice>
      )}
      {scan?.result && <ConfigNotices coverage={scan.result.coverage} />}
      {scan?.result && <SuppressionNotices result={scan.result} />}
      {scan?.result && <CoverageTable coverage={scan.result.coverage} />}
      {error && <Notice tone="error">{error}</Notice>}
    </Card>
  );
}
