import { useCallback, useState } from "react";
import type { AuthStatus, SessionInfo } from "../../../shared/api-types";
import { apiGet, apiPost } from "../../api/client";
import { Card, Notice } from "../../components/ui/Card";
import { usePolling } from "../../hooks/use-polling";

const CHECK_LABELS: Record<string, string> = {
  repository: "Repository",
  github_identity: "GitHub identity",
  owner_approval: "Owner approval",
  current_access: "Current access",
  contribution: "Merged contribution",
};

/** Only https links to github.com become clickable; anything else is shown as text. */
export function isGitHubUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.hostname === "github.com";
  } catch {
    return false;
  }
}

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

  const signOut = async (): Promise<void> => {
    update(await apiPost<AuthStatus>("/api/auth/sign-out"));
  };

  return (
    <Card
      title="Authorization"
      step={1}
      actions={
        status?.status === "done" ? (
          <button type="button" className="button" onClick={() => void signOut()}>
            Sign out of GitHub
          </button>
        ) : null
      }
    >
      <p className="muted">
        Project <strong>{session.projectName}</strong>. PGARD checks owner approval, your current
        access and a merged contribution before every scan.
      </p>
      {!session.isClientIdConfigured && (
        <Notice tone="warning">
          PGARD_GITHUB_APP_CLIENT_ID is not set. A registered PGARD GitHub App is required to verify
          your GitHub identity; until then every scan is blocked.
        </Notice>
      )}
      {status?.deviceCode && (
        <div className="device-code" role="status">
          <p>
            Open{" "}
            {isGitHubUrl(status.deviceCode.verificationUri) ? (
              <a href={status.deviceCode.verificationUri} target="_blank" rel="noreferrer noopener">
                {status.deviceCode.verificationUri}
              </a>
            ) : (
              <code>{status.deviceCode.verificationUri}</code>
            )}{" "}
            and enter this code:
          </p>
          <p className="code">{status.deviceCode.userCode}</p>
          <p className="muted">
            Expires in about {Math.max(1, Math.round(status.deviceCode.expiresIn / 60))} min.
          </p>
        </div>
      )}
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
                  <td>{CHECK_LABELS[check.id] ?? check.id}</td>
                  <td>
                    <span className={`badge badge-${check.status}`}>{check.status}</span>
                  </td>
                  <td>{check.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="muted">This result is not stored; every scan checks again.</p>
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
