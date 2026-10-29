import { Button } from "../../components/ui/Button";
import { HelpTip } from "../../components/ui/HelpTip";
import { useI18n } from "../../i18n/I18nProvider";
import { signOutTexts } from "./sign-in-text";
import type { Authorization } from "./use-authorization";

/**
 * The two sign-out actions, at the right end of the tab row: end this dashboard's GitHub session
 * only, or also remove the sign-in from the OS keychain. Shown only when there is a session to
 * end. Errors appear in the Authorization section like any other authorization error.
 */
export function SessionActions({ authorization }: { authorization: Authorization }) {
  const { m } = useI18n();
  const { status, signOut } = authorization;
  const { labels, hints } = signOutTexts(m);
  const canEndSession = status?.status === "done" || status?.storedSignIn.status === "stored";
  const canRemoveStored = status?.storedSignIn.status === "stored";
  if (!canEndSession && !canRemoveStored) return null;
  const actions = (
    <>
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
    </>
  );
  // Wide screens show the buttons beside the tabs; narrow ones put them behind a small menu
  // button at the end of the tab row. CSS shows exactly one (the other is display: none, so
  // assistive technology meets the buttons once).
  return (
    <>
      <div className="session-actions" role="group" aria-label={m.help.session}>
        {actions}
      </div>
      <details className="session-menu">
        <summary>{m.help.session}</summary>
        <div className="session-menu-body" role="group" aria-label={m.help.session}>
          {actions}
        </div>
      </details>
    </>
  );
}
