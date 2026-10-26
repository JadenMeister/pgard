import { useCallback, useEffect, useState } from "react";
import type { AuthStatus, SessionInfo, SignOutRequestDto } from "../../../shared/api-types";
import { apiGet, apiPost } from "../../api/client";
import { DeviceCodeNotice } from "../../components/github/DeviceCodeNotice";
import { Card, Notice } from "../../components/ui/Card";
import { usePolling } from "../../hooks/use-polling";
import { InstallAppNotice } from "./InstallAppNotice";
import {
  describeGitHubApp,
  describeStoredSignIn,
  SIGN_OUT_HINTS,
  SIGN_OUT_LABELS,
} from "./sign-in-text";

const CHECK_LABELS: Record<string, string> = {
  repository: "Repository",
  github_identity: "GitHub identity",
  owner_approval: "Owner approval",
  current_access: "Current access",
  contribution: "Merged contribution",
};

interface AuthorizationPanelProps {
  session: SessionInfo;
  onStatus: (status: AuthStatus) => void;
}

/** Runs the same authorization gate a scan runs and shows each check's reason. */
export function AuthorizationPanel({ session, onStatus }: AuthorizationPanelProps) {
  const [status, setStatus] = useState<AuthStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const update = useCallback(
    (next: AuthStatus) => {
      setStatus(next);
      onStatus(next);
    },
    [onStatus],
  );

  usePolling(
    async () => update(await apiGet<AuthStatus>("/api/auth")),
    1000,
    status?.status === "running",
  );

  const verify = async (): Promise<void> => {
    setError(null);
    try {
      update(await apiPost<AuthStatus>("/api/auth/verify"));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Request failed.");
    }
  };

  // Load the current sign-in state once, so a keychain sign-in is visible before the first check.
  useEffect(() => {
    void apiGet<AuthStatus>("/api/auth")
      .then(update)
      .catch(() => undefined);
  }, [update]);

  const signOut = async (removeStored: boolean): Promise<void> => {
    setError(null);
    try {
      const body: SignOutRequestDto = { removeStored };
      update(await apiPost<AuthStatus>("/api/auth/sign-out", body));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Request failed.");
    }
  };

  const signInLine = status ? describeStoredSignIn(status.storedSignIn) : null;
  const githubAppLine = describeGitHubApp(session.githubApp);
  const canEndSession = status?.status === "done" || status?.storedSignIn.status === "stored";
  const canRemoveStored = status?.storedSignIn.status === "stored";

  return (
    <Card
      title="Authorization"
      step={1}
      actions={
        canEndSession || canRemoveStored ? (
          <span className="button-row">
            {canEndSession && (
              <button
                type="button"
                className="button"
                title={SIGN_OUT_HINTS.sessionOnly}
                onClick={() => void signOut(false)}
              >
                {SIGN_OUT_LABELS.sessionOnly}
              </button>
            )}
            {canRemoveStored && (
              <button
                type="button"
                className="button"
                title={SIGN_OUT_HINTS.removeStored}
                onClick={() => void signOut(true)}
              >
                {SIGN_OUT_LABELS.removeStored}
              </button>
            )}
          </span>
        ) : null
      }
    >
      <p className="muted">
        Project <strong>{session.projectName}</strong>. PGARD checks owner approval, your current
        access and a merged contribution before every scan.
      </p>
      {githubAppLine?.tone === "info" && <p className="muted">{githubAppLine.text}</p>}
      {githubAppLine?.tone === "warning" && <Notice tone="warning">{githubAppLine.text}</Notice>}
      {session.githubAppWarning && <Notice tone="warning">{session.githubAppWarning}</Notice>}
      {signInLine && <p className="muted">{signInLine}</p>}
      {(canEndSession || canRemoveStored) && (
        <p className="muted">
          {SIGN_OUT_LABELS.sessionOnly}: {SIGN_OUT_HINTS.sessionOnly}{" "}
          {canRemoveStored && (
            <>
              {SIGN_OUT_LABELS.removeStored}: {SIGN_OUT_HINTS.removeStored}
            </>
          )}
        </p>
      )}
      {status?.signInNotice && <Notice tone="info">{status.signInNotice}</Notice>}
      {status?.deviceCode && <DeviceCodeNotice deviceCode={status.deviceCode} />}
      {status?.status === "running" && !status.deviceCode && <p className="muted">Checking...</p>}
      {status?.summary && (
        <>
          <p
            className={
              status.summary.decision === "allowed" ? "decision allowed" : "decision blocked"
            }
          >
            {status.summary.decision === "allowed" ? "Allowed" : "Blocked - no analysis will run"}
            {status.repo ? ` - ${status.repo}` : ""}
          </p>
          <table className="table">
            <thead>
              <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {status.summary.checks.map((check) => (
                <tr key={check.id}>
                  <td data-label="Check">{CHECK_LABELS[check.id] ?? check.id}</td>
                  <td data-label="Status">
                    <span className={`badge badge-${check.status}`}>{check.status}</span>
                  </td>
                  <td data-label="Reason">{check.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {status.status === "done" && status.remedy && (
            <InstallAppNotice
              remedy={status.remedy}
              waitEndsAt={status.installWaitEndsAt}
              onInstalled={() => void verify()}
            />
          )}
          <p className="muted">This result is not stored; every scan checks again.</p>
          {typeof status.expiresAt === "number" && (
            <p className="muted">
              Local service discovery and probes stay open until{" "}
              {new Date(status.expiresAt).toLocaleTimeString()}; check again after that.
            </p>
          )}
        </>
      )}
      {status?.message && <Notice tone="error">{status.message}</Notice>}
      {error && <Notice tone="error">{error}</Notice>}
      <button
        type="button"
        className="button primary"
        disabled={status?.status === "running"}
        onClick={() => void verify()}
      >
        {status?.summary ? "Check again" : "Verify project"}
      </button>
    </Card>
  );
}
