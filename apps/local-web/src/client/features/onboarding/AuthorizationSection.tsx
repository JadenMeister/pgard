import type { SessionInfo } from "../../../shared/api-types";
import { DeviceCodeNotice } from "../../components/github/DeviceCodeNotice";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { HelpTip } from "../../components/ui/HelpTip";
import { Notice } from "../../components/ui/Notice";
import { Section } from "../../components/ui/Section";
import { formatTime } from "../../i18n/format";
import { useI18n } from "../../i18n/I18nProvider";
import { InstallAppNotice } from "./InstallAppNotice";
import { describeGitHubApp, describeStoredSignIn, signOutTexts } from "./sign-in-text";
import type { Authorization } from "./use-authorization";

export const AUTHORIZATION_SECTION_ID = "authorization";

/**
 * What the authorization gate said: sign-in prompts, the fix for a blocked check (install the
 * App, ask an owner), and the five checks with their reasons in a details block that is open
 * when the check is blocked. The header strip starts checks; this section explains them.
 */
export function AuthorizationSection({
  session,
  authorization,
}: {
  session: SessionInfo;
  authorization: Authorization;
}) {
  const { m, language } = useI18n();
  const { status, error, verify, signOut } = authorization;
  const { labels, hints } = signOutTexts(m);
  const checkLabels: Record<string, string> = m.auth.checks;
  const statusLabels: Record<string, string> = m.status;
  const signInLine = status ? describeStoredSignIn(status.storedSignIn, m) : null;
  const githubAppLine = describeGitHubApp(session.githubApp, m);
  const canEndSession = status?.status === "done" || status?.storedSignIn.status === "stored";
  const canRemoveStored = status?.storedSignIn.status === "stored";
  const isBlocked = status?.summary?.decision === "blocked";

  return (
    <div id={AUTHORIZATION_SECTION_ID} tabIndex={-1} className="anchor-target">
      <Section
        title={m.cards.authorization}
        meta={
          status?.summary ? (
            <span className={`decision ${isBlocked ? "blocked" : "allowed"}`}>
              {isBlocked ? m.auth.blocked : m.auth.allowed}
              {status.repo ? ` · ${status.repo}` : ""}
            </span>
          ) : null
        }
        help={<p>{m.auth.intro}</p>}
      >
        {githubAppLine?.tone === "warning" && <Notice tone="warning">{githubAppLine.text}</Notice>}
        {session.githubAppWarning && <Notice tone="warning">{session.githubAppWarning}</Notice>}
        {status?.signInNotice && <Notice tone="info">{status.signInNotice}</Notice>}
        {status?.deviceCode && <DeviceCodeNotice deviceCode={status.deviceCode} />}
        {status?.status === "running" && !status.deviceCode && (
          <p className="muted" role="status">
            {m.auth.checking}
          </p>
        )}
        {status?.status === "done" && status.accessNote === "app_covers_all_repositories" && (
          <Notice tone="warning">
            {m.install.allRepositoriesNote(status.repo ?? m.install.thisRepository)}
          </Notice>
        )}
        {status?.status === "done" && status.remedy && (
          <InstallAppNotice
            remedy={status.remedy}
            repo={status.repo}
            waitEndsAt={status.installWaitEndsAt}
            onInstalled={() => void verify()}
          />
        )}
        {status?.message && <Notice tone="error">{status.message}</Notice>}
        {error && <Notice tone="error">{error}</Notice>}
        {status?.summary ? (
          <details className="disclosure" open={isBlocked}>
            <summary>{m.help.authDetails}</summary>
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
                      <Badge kind={check.status}>
                        {statusLabels[check.status] ?? check.status}
                      </Badge>
                    </td>
                    <td data-label={m.auth.columns.reason}>{check.reason}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <ul className="fact-list">
              {githubAppLine?.tone === "info" && <li>{githubAppLine.text}</li>}
              {signInLine && <li>{signInLine}</li>}
              <li>{m.auth.notStored}</li>
              {typeof status.expiresAt === "number" && (
                <li>{m.auth.expiresAt(formatTime(status.expiresAt, language))}</li>
              )}
            </ul>
          </details>
        ) : (
          signInLine && <p className="muted small">{signInLine}</p>
        )}
        {(canEndSession || canRemoveStored) && (
          <div className="button-row">
            {canEndSession && (
              <Button size="sm" title={hints.sessionOnly} onClick={() => void signOut(false)}>
                {labels.sessionOnly}
              </Button>
            )}
            {canRemoveStored && (
              <Button size="sm" title={hints.removeStored} onClick={() => void signOut(true)}>
                {labels.removeStored}
              </Button>
            )}
            <HelpTip label={m.help.signOut}>
              <p>
                <strong>{labels.sessionOnly}</strong>: {hints.sessionOnly}
              </p>
              {canRemoveStored && (
                <p>
                  <strong>{labels.removeStored}</strong>: {hints.removeStored}
                </p>
              )}
            </HelpTip>
          </div>
        )}
      </Section>
    </div>
  );
}
