import type { TargetInfo } from "../../../shared/api-types";
import { Button } from "../../components/ui/Button";
import { HelpTip } from "../../components/ui/HelpTip";
import { Notice } from "../../components/ui/Notice";
import { useI18n } from "../../i18n/I18nProvider";
import { authState } from "../onboarding/auth-state";
import type { Authorization } from "../onboarding/use-authorization";
import { formatElapsed } from "./scan-progress";
import { SCAN_SCOPES, type ScanControl } from "./use-scan";

interface ScanStripProps {
  projectName: string;
  authorization: Authorization;
  control: ScanControl;
  target: TargetInfo | null;
  /** Shows the authorization section (overview) and moves focus to it. */
  onShowAuthorization: () => void;
}

/**
 * The slim header strip: which repository, where the authorization gate stands, the scan scopes
 * as compact toggles and the run button. Everything else lives in the views below.
 */
export function ScanStrip({
  projectName,
  authorization,
  control,
  target,
  onShowAuthorization,
}: ScanStripProps) {
  const { m } = useI18n();
  const status = authorization.status;
  const state = authState(status);
  const login = status?.storedSignIn.status === "stored" ? status.storedSignIn.login : null;
  const { scopes, isRunning } = control;
  return (
    <section className="strip" aria-label={m.strip.label}>
      <div className="wrap strip-in">
        <div className="strip-id">
          <h1 className="strip-title">{status?.repo ?? projectName}</h1>
          <span className={`auth-state auth-${state}`}>
            {m.strip.auth[state]}
            {login !== null && state === "allowed" ? ` · ${login}` : ""}
          </span>
          <button type="button" className="link-button" onClick={onShowAuthorization}>
            {m.strip.authDetails}
          </button>
          <Button
            size="sm"
            disabled={status?.status === "running"}
            onClick={() => void authorization.verify()}
          >
            {status?.summary ? m.auth.recheck : m.auth.verify}
          </Button>
        </div>
        <div className="strip-scan">
          <fieldset className="scope-toggles" disabled={isRunning}>
            <legend className="sr-only">{m.scan.scope}</legend>
            {SCAN_SCOPES.map((scope) => (
              <label key={scope} className="scope-toggle" title={m.scan.scopes[scope].hint}>
                <input
                  type="checkbox"
                  checked={scopes.includes(scope)}
                  onChange={() => control.toggleScope(scope)}
                />
                {m.scan.scopes[scope].label}
              </label>
            ))}
            <HelpTip label={m.scan.scope}>
              <ul className="fact-list">
                {SCAN_SCOPES.map((scope) => (
                  <li key={scope}>
                    <strong>{m.scan.scopes[scope].label}</strong>: {m.scan.scopes[scope].hint}
                  </li>
                ))}
              </ul>
            </HelpTip>
          </fieldset>
          <span className="strip-target">
            {target === null ? m.strip.noTarget : m.strip.target(target.origin)}
          </span>
          {isRunning && (
            <span className="strip-elapsed">
              {m.strip.scanning(formatElapsed(control.elapsedSeconds))}
            </span>
          )}
          {isRunning ? (
            <Button size="sm" onClick={() => void control.cancel()}>
              {m.scan.cancel}
            </Button>
          ) : (
            <Button
              size="sm"
              variant="primary"
              disabled={scopes.length === 0}
              onClick={() => void control.start()}
            >
              {m.scan.run}
            </Button>
          )}
        </div>
      </div>
      {(scopes.includes("web") && target === null) || control.error ? (
        <div className="wrap strip-notes">
          {scopes.includes("web") && target === null && (
            <Notice tone="warning">{m.scan.noWebTarget}</Notice>
          )}
          {control.error && <Notice tone="error">{control.error}</Notice>}
        </div>
      ) : null}
    </section>
  );
}
