import { useCallback, useEffect, useState } from "react";
import type { AuthStatus, SessionInfo, SignOutRequestDto } from "../../../shared/api-types";
import { apiGet, apiPost } from "../../api/client";
import { DeviceCodeNotice } from "../../components/github/DeviceCodeNotice";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { Card } from "../../components/ui/Card";
import { Notice } from "../../components/ui/Notice";
import { usePolling } from "../../hooks/use-polling";
import { useI18n } from "../../i18n/I18nProvider";
import { InstallAppNotice } from "./InstallAppNotice";
import { describeGitHubApp, describeStoredSignIn, signOutTexts } from "./sign-in-text";

interface AuthorizationPanelProps {
  session: SessionInfo;
  onStatus: (status: AuthStatus) => void;
}

/** Runs the same authorization gate a scan runs and shows each check's reason. */
export function AuthorizationPanel({ session, onStatus }: AuthorizationPanelProps) {
  const { m } = useI18n();
  const { labels: SIGN_OUT_LABELS, hints: SIGN_OUT_HINTS } = signOutTexts(m);
  const checkLabels: Record<string, string> = m.auth.checks;
  const statusLabels: Record<string, string> = m.status;
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
      setError(caught instanceof Error ? caught.message : m.common.requestFailed);
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
      setError(caught instanceof Error ? caught.message : m.common.requestFailed);
    }
  };

  const signInLine = status ? describeStoredSignIn(status.storedSignIn, m) : null;
  const githubAppLine = describeGitHubApp(session.githubApp, m);
  const canEndSession = status?.status === "done" || status?.storedSignIn.status === "stored";
  const canRemoveStored = status?.storedSignIn.status === "stored";

  return (
    <Card
      title={m.cards.authorization}
      step={1}
      actions={
        canEndSession || canRemoveStored ? (
          <>
            {canEndSession && (
              <Button title={SIGN_OUT_HINTS.sessionOnly} onClick={() => void signOut(false)}>
                {SIGN_OUT_LABELS.sessionOnly}
              </Button>
            )}
            {canRemoveStored && (
              <Button title={SIGN_OUT_HINTS.removeStored} onClick={() => void signOut(true)}>
                {SIGN_OUT_LABELS.removeStored}
              </Button>
            )}
          </>
        ) : null
      }
    >
      <p className="muted">
        {m.auth.projectLabel} <strong>{session.projectName}</strong>. {m.auth.intro}
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
      {status?.status === "running" && !status.deviceCode && (
        <p className="muted">{m.auth.checking}</p>
      )}
      {status?.summary && (
        <>
          <p
            className={
              status.summary.decision === "allowed" ? "decision allowed" : "decision blocked"
            }
          >
            {status.summary.decision === "allowed" ? m.auth.allowed : m.auth.blocked}
            {status.repo ? ` - ${status.repo}` : ""}
          </p>
          <table className="table">
            <thead>
              <tr>
                <th>{m.auth.columns.check}</th>
                <th>{m.auth.columns.status}</th>
                <th>{m.auth.columns.reason}</th>
              </tr>
            </thead>
            <tbody>
              {status.summary.checks.map((check) => (
                <tr key={check.id}>
                  <td data-label={m.auth.columns.check}>{checkLabels[check.id] ?? check.id}</td>
                  <td data-label={m.auth.columns.status}>
                    <Badge kind={check.status}>{statusLabels[check.status] ?? check.status}</Badge>
                  </td>
                  <td data-label={m.auth.columns.reason}>{check.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {status.status === "done" && status.accessNote === "app_covers_all_repositories" && (
            <Notice tone="warning">
              {m.install.allRepositoriesNote(status.repo ?? m.install.thisRepository)}
            </Notice>
          )}
          {status.status === "done" && status.remedy && (
            <InstallAppNotice
              remedy={status.remedy}
              repo={status.repo}
              waitEndsAt={status.installWaitEndsAt}
              onInstalled={() => void verify()}
            />
          )}
          <p className="muted">{m.auth.notStored}</p>
          {typeof status.expiresAt === "number" && (
            <p className="muted">
              {m.auth.expiresAt(new Date(status.expiresAt).toLocaleTimeString())}
            </p>
          )}
        </>
      )}
      {status?.message && <Notice tone="error">{status.message}</Notice>}
      {error && <Notice tone="error">{error}</Notice>}
      <Button
        variant="primary"
        disabled={status?.status === "running"}
        onClick={() => void verify()}
      >
        {status?.summary ? m.auth.recheck : m.auth.verify}
      </Button>
    </Card>
  );
}
