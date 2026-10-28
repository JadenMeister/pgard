import { useState } from "react";
import type { ScanScope } from "@pgard/findings";
import type { ScanStatus } from "../../../shared/api-types";
import { apiGet, apiPost } from "../../api/client";
import { usePolling } from "../../hooks/use-polling";
import { useI18n } from "../../i18n/I18nProvider";
import { useElapsedSeconds } from "./ScanProgress";

export const SCAN_SCOPES: readonly ScanScope[] = ["code", "history", "web"];

export interface ScanControl {
  scan: ScanStatus | null;
  scopes: ScanScope[];
  toggleScope: (scope: ScanScope) => void;
  isRunning: boolean;
  elapsedSeconds: number;
  error: string | null;
  start: () => Promise<void>;
  cancel: () => Promise<void>;
}

/** The scan through the local server (scan-core, gate included): scopes, start, cancel, polling. */
export function useScan(): ScanControl {
  const { m } = useI18n();
  const [scan, setScan] = useState<ScanStatus | null>(null);
  const [scopes, setScopes] = useState<ScanScope[]>(["code", "history"]);
  const [error, setError] = useState<string | null>(null);
  const isRunning = scan?.status === "running";
  const elapsedSeconds = useElapsedSeconds(isRunning);

  usePolling(async () => setScan(await apiGet<ScanStatus>("/api/scan")), 1000, isRunning);

  const toggleScope = (scope: ScanScope): void => {
    setScopes((current) =>
      current.includes(scope) ? current.filter((entry) => entry !== scope) : [...current, scope],
    );
  };

  const start = async (): Promise<void> => {
    setError(null);
    try {
      setScan(await apiPost<ScanStatus>("/api/scan", { scopes }));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : m.common.requestFailed);
    }
  };

  const cancel = async (): Promise<void> => {
    setScan(await apiPost<ScanStatus>("/api/scan/cancel"));
  };

  return { scan, scopes, toggleScope, isRunning, elapsedSeconds, error, start, cancel };
}
