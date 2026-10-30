import { useEffect, useState } from "react";
import type {
  AuthStatus,
  PortListResponse,
  ServiceIdentityDto,
  TargetInfo,
} from "../../../shared/api-types";
import { apiGet, apiPost } from "../../api/client";
import { Button } from "../../components/ui/Button";
import { Section } from "../../components/ui/Section";
import { Notice } from "../../components/ui/Notice";
import { useI18n } from "../../i18n/I18nProvider";
import {
  isAuthorizationRequiredError,
  isPortAccessExpired,
  msUntilPortAccessExpires,
  portAccessMessage,
} from "./port-access";
import { usePortAccess } from "./use-port-access";
import { RelatednessNotice, ServiceList } from "./ServiceList";

interface TargetPanelProps {
  /** Latest authorization status; nothing is discovered or probed until it reports allowed. */
  auth: AuthStatus | null;
  presetPort: number | null;
  target: TargetInfo | null;
  onTarget: (target: TargetInfo | null) => void;
}

function parsePortInput(value: string): number | null {
  if (!/^[0-9]{1,5}$/.test(value)) return null;
  const port = Number(value);
  return port >= 1 && port <= 65535 ? port : null;
}

/**
 * Local service selection. The server probes the port and shows its identity; only then can the
 * user confirm it. The browser never builds the target itself.
 */
export function TargetPanel({ auth, presetPort, target, onTarget }: TargetPanelProps) {
  const { m } = useI18n();
  const [services, setServices] = useState<PortListResponse | null>(null);
  const [otherPort, setOtherPort] = useState(presetPort === null ? "" : String(presetPort));
  const [identity, setIdentity] = useState<ServiceIdentityDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isBusy, setIsBusy] = useState(false);
  // Set when the allowed check reaches `expiresAt`, or when the server refuses a request with
  // `authorization_required`; a new authorization status clears it.
  const [isExpired, setIsExpired] = useState(false);
  useEffect(() => {
    setIsExpired(isPortAccessExpired(auth, Date.now()));
    const delay = msUntilPortAccessExpires(auth, Date.now());
    if (delay === null) return undefined;
    const timer = setTimeout(() => setIsExpired(true), delay + 1);
    return () => clearTimeout(timer);
  }, [auth]);
  const blockedMessage =
    portAccessMessage(auth, Date.now(), m) ?? (isExpired ? m.target.access.expired : null);
  const showError = (caught: unknown): void => {
    if (isAuthorizationRequiredError(caught)) {
      setIsExpired(true);
      return;
    }
    setError(caught instanceof Error ? caught.message : m.common.requestFailed);
  };
  // Requests start once per allowed authorization; the preset port still needs explicit
  // confirmation. Each response is kept only if that authorization is still the current one.
  const access = usePortAccess(auth, presetPort, {
    listPorts: () => void refresh(),
    probe: (port) => void probe(port),
    reset: () => {
      // Authorization is missing, running again, blocked or signed out: forget what was found.
      setServices(null);
      setIdentity(null);
      setError(null);
    },
  });

  const refresh = async (): Promise<void> => {
    const token = access.currentToken();
    if (token === null) return;
    setIsBusy(true);
    try {
      const response = await apiGet<PortListResponse>("/api/ports");
      if (access.isCurrent(token)) setServices(response);
    } catch (caught) {
      if (access.isCurrent(token)) {
        showError(caught);
      }
    } finally {
      setIsBusy(false);
    }
  };

  const probe = async (port: number): Promise<void> => {
    const token = access.currentToken();
    if (token === null) return;
    setError(null);
    setIsBusy(true);
    try {
      const response = await apiPost<ServiceIdentityDto>("/api/ports/probe", { port });
      if (access.isCurrent(token)) setIdentity(response);
    } catch (caught) {
      if (access.isCurrent(token)) {
        showError(caught);
      }
    } finally {
      setIsBusy(false);
    }
  };

  const confirm = async (): Promise<void> => {
    if (identity === null) return;
    try {
      onTarget(
        await apiPost<TargetInfo>("/api/target/confirm", {
          port: identity.port,
          isConfirmed: true,
        }),
      );
      setIdentity(null);
    } catch (caught) {
      showError(caught);
    }
  };

  const clear = async (): Promise<void> => {
    await apiPost("/api/target/clear");
    onTarget(null);
  };

  const otherPortValue = parsePortInput(otherPort.trim());

  return (
    <Section title={m.cards.target} help={<p>{m.target.intro}</p>}>
      {target !== null ? (
        <div className="target-confirmed">
          <p>
            {m.target.confirmedTarget} <code>{target.origin}</code>
            {target.title ? ` - ${target.title}` : ""}
          </p>
          <Button onClick={() => void clear()}>{m.target.chooseAnother}</Button>
        </div>
      ) : blockedMessage !== null ? (
        <Notice tone={auth?.status === "running" || auth === null ? "info" : "warning"}>
          {blockedMessage}
        </Notice>
      ) : (
        <>
          <div className="service-list">
            <ServiceList
              services={services?.services ?? []}
              isBusy={isBusy}
              onPick={(port) => void probe(port)}
            />
            {services !== null && services.services.length === 0 && (
              <p className="muted">{m.target.noServices(services.note || null)}</p>
            )}
          </div>
          <form
            className="inline-form"
            onSubmit={(event) => {
              event.preventDefault();
              if (otherPortValue !== null) void probe(otherPortValue);
            }}
          >
            <label>
              {m.target.otherPort}
              <input
                inputMode="numeric"
                value={otherPort}
                maxLength={5}
                onChange={(event) => setOtherPort(event.target.value)}
                aria-invalid={otherPort !== "" && otherPortValue === null}
              />
            </label>
            <Button type="submit" disabled={otherPortValue === null || isBusy}>
              {m.target.check}
            </Button>
            <Button disabled={isBusy} onClick={() => void refresh()}>
              {m.target.refresh}
            </Button>
          </form>
          {identity !== null && (
            <div className="identity" role="group" aria-label={m.target.identityLabel}>
              <dl>
                <dt>{m.target.url}</dt>
                <dd>
                  <code>{identity.url}</code>
                </dd>
                <dt>{m.target.status}</dt>
                <dd>
                  {identity.isHttp
                    ? identity.status
                    : m.target.noHttp(identity.error ?? m.common.unknown)}
                </dd>
                <dt>{m.target.title}</dt>
                <dd>{identity.title ?? m.common.none}</dd>
                <dt>{m.target.technology}</dt>
                <dd>{identity.inferredTechnologies.join(", ") || m.common.unknown}</dd>
              </dl>
              {identity.hasUnfollowedRedirect && (
                <Notice tone="warning">{m.target.redirect}</Notice>
              )}
              {identity.isHttp ? (
                <>
                  <RelatednessNotice relatedness={identity.relatedness} />
                  <div className="confirm-row">
                    <p>{m.target.question}</p>
                    <Button variant="primary" onClick={() => void confirm()}>
                      {m.target.yes}
                    </Button>
                    <Button onClick={() => setIdentity(null)}>{m.target.no}</Button>
                  </div>
                </>
              ) : (
                <Notice tone="warning">{m.target.notHttp}</Notice>
              )}
            </div>
          )}
        </>
      )}
      {error && <Notice tone="error">{error}</Notice>}
    </Section>
  );
}
