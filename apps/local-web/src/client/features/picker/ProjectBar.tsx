import { useState } from "react";
import type { ProjectInfo } from "../../../shared/api-types";
import { apiPost, getProjectEpoch } from "../../api/client";
import { Button } from "../../components/ui/Button";
import { Notice } from "../../components/ui/Notice";
import { useI18n } from "../../i18n/I18nProvider";
import { pickerErrorText } from "./error-text";

/**
 * The chosen project (name and `owner/name`) above the existing authorization flow, with
 * **Change project** (disabled while a scan or a check runs, with the reason) and, while a check
 * runs or waits for the GitHub sign-in, **Cancel check**, which makes Change project available
 * again. Picker mode only.
 */
export function ProjectBar({
  project,
  canChange = true,
  isScanRunning,
  isAuthRunning,
  onChanged,
}: {
  project: ProjectInfo;
  /** Picker mode only: `pgard dashboard` has one project and no Change project. */
  canChange?: boolean;
  isScanRunning: boolean;
  /** A check or an owner-approval re-check is running: Change project waits for it. */
  isAuthRunning: boolean;
  onChanged: () => void;
}) {
  const { m } = useI18n();
  const [error, setError] = useState<string | null>(null);
  const blockedReason = isScanRunning
    ? m.picker.project.changeBlockedScan
    : isAuthRunning
      ? m.picker.project.changeBlockedAuth
      : null;
  const change = (): void => {
    setError(null);
    apiPost("/api/picker/clear", { epoch: getProjectEpoch() })
      .then(onChanged)
      .catch((caught: unknown) => setError(pickerErrorText(m, caught)));
  };
  const cancelCheck = (): void => {
    setError(null);
    apiPost("/api/auth/cancel").catch((caught: unknown) => setError(pickerErrorText(m, caught)));
  };
  const canCancel = isAuthRunning;
  // `pgard dashboard`: only the Cancel check button, and only while there is something to cancel
  // (a check that waits for the GitHub sign-in, or a blocked Git, #377).
  if (!canChange && !canCancel) return null;
  return (
    <div className="projectbar">
      <div className="wrap projectbar-in">
        <p className="projectbar-name">
          <span className="muted small">{m.picker.project.label}</span>{" "}
          <strong>{project.name}</strong>
          {project.repo !== null && <span className="pick-repo"> {project.repo}</span>}
        </p>
        <div className="projectbar-actions">
          {canCancel && (
            <Button size="sm" title={m.picker.project.cancelCheckHint} onClick={cancelCheck}>
              {m.picker.project.cancelCheck}
            </Button>
          )}
          {canChange && (
            <Button size="sm" disabled={blockedReason !== null} onClick={change}>
              {m.picker.project.change}
            </Button>
          )}
          {canChange && blockedReason !== null && (
            <span className="muted small">{blockedReason}</span>
          )}
        </div>
        {error !== null && <Notice tone="error">{error}</Notice>}
      </div>
    </div>
  );
}
