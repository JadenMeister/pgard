import { useState } from "react";
import type { ScanScope } from "@pgard/findings";
import type { ScanStatus, TargetInfo } from "../../../shared/api-types";
import { apiGet, apiPost } from "../../api/client";
import { Card, Notice } from "../../components/ui/Card";
import { usePolling } from "../../hooks/use-polling";
import { CoverageTable } from "./CoverageTable";

const SCOPE_OPTIONS: ReadonlyArray<{ scope: ScanScope; label: string; hint: string }> = [
  { scope: "code", label: "Code", hint: "current code, configuration and dependencies" },
  {
    scope: "history",
    label: "Git history",
    hint: "tracked files and past commits (secrets, risky files)",
  },
  {
    scope: "web",
    label: "Local web service",
    hint: "anonymous GET checks of the confirmed target",
  },
];

interface ScanPanelProps {
  target: TargetInfo | null;
  scan: ScanStatus | null;
  onScan: (scan: ScanStatus) => void;
}

/** Starts a scan through the local server (scan-core, gate included) and shows progress. */
export function ScanPanel({ target, scan, onScan }: ScanPanelProps) {
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
      setError(caught instanceof Error ? caught.message : "Request failed.");
    }
  };

  const cancel = async (): Promise<void> => {
    onScan(await apiPost<ScanStatus>("/api/scan/cancel"));
  };

  return (
    <Card title="Scan" step={3}>
      <fieldset className="scopes" disabled={isRunning}>
        <legend>Scope</legend>
        {SCOPE_OPTIONS.map((option) => (
          <label key={option.scope} className="scope">
            <input
              type="checkbox"
              checked={scopes.includes(option.scope)}
              onChange={() => toggle(option.scope)}
            />
            <span>
              {option.label} <span className="muted">- {option.hint}</span>
            </span>
          </label>
        ))}
      </fieldset>
      {scopes.includes("web") && target === null && (
        <Notice tone="warning">
          No confirmed web target: the web scope will be recorded as not tested and the scan will be
          partial.
        </Notice>
      )}
      <div className="button-row">
        <button
          type="button"
          className="button primary"
          disabled={isRunning || scopes.length === 0}
          onClick={() => void start()}
        >
          Run scan
        </button>
        {isRunning && (
          <button type="button" className="button" onClick={() => void cancel()}>
            Cancel
          </button>
        )}
      </div>
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
      {scan?.result && <CoverageTable coverage={scan.result.coverage} />}
      {error && <Notice tone="error">{error}</Notice>}
    </Card>
  );
}
