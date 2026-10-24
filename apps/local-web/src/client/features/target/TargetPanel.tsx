import { useEffect, useState } from "react";
import type { PortListResponse, ServiceIdentityDto, TargetInfo } from "../../../shared/api-types";
import { apiGet, apiPost } from "../../api/client";
import { Card, Notice } from "../../components/ui/Card";

interface TargetPanelProps {
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
export function TargetPanel({ presetPort, target, onTarget }: TargetPanelProps) {
  const [services, setServices] = useState<PortListResponse | null>(null);
  const [otherPort, setOtherPort] = useState(presetPort === null ? "" : String(presetPort));
  const [identity, setIdentity] = useState<ServiceIdentityDto | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isBusy, setIsBusy] = useState(false);

  const refresh = async (): Promise<void> => {
    setIsBusy(true);
    try {
      setServices(await apiGet<PortListResponse>("/api/ports"));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Request failed.");
    } finally {
      setIsBusy(false);
    }
  };

  const probe = async (port: number): Promise<void> => {
    setError(null);
    setIsBusy(true);
    try {
      setIdentity(await apiPost<ServiceIdentityDto>("/api/ports/probe", { port }));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Request failed.");
    } finally {
      setIsBusy(false);
    }
  };

  useEffect(() => {
    void refresh();
    if (presetPort !== null) void probe(presetPort);
    // Runs once on mount; the preset port still needs explicit confirmation.
  }, []);

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
      setError(caught instanceof Error ? caught.message : "Request failed.");
    }
  };

  const clear = async (): Promise<void> => {
    await apiPost("/api/target/clear");
    onTarget(null);
  };

  const otherPortValue = parsePortInput(otherPort.trim());

  return (
    <Card title="Local web service (optional)" step={2}>
      {target !== null ? (
        <div className="target-confirmed">
          <p>
            Confirmed target: <code>{target.origin}</code>
            {target.title ? ` - ${target.title}` : ""}
          </p>
          <button type="button" className="button" onClick={() => void clear()}>
            Choose another service
          </button>
        </div>
      ) : (
        <>
          <p className="muted">
            Pick the project's service on 127.0.0.1. The list can be incomplete; you can always
            enter a port. The port number alone says nothing about which project it belongs to.
          </p>
          <div className="service-list">
            {services?.services.map((service) => (
              <button
                type="button"
                key={service.port}
                className="service"
                disabled={isBusy}
                onClick={() => void probe(service.port)}
              >
                <code>http://127.0.0.1:{service.port}</code>
                <span className="muted">
                  {service.status ?? ""} {service.title ?? ""}{" "}
                  {service.processName ? `(${service.processName})` : ""}
                </span>
              </button>
            ))}
            {services !== null && services.services.length === 0 && (
              <p className="muted">
                No local HTTP services found{services.note ? ` (${services.note})` : ""}.
              </p>
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
              Other port
              <input
                inputMode="numeric"
                value={otherPort}
                maxLength={5}
                onChange={(event) => setOtherPort(event.target.value)}
                aria-invalid={otherPort !== "" && otherPortValue === null}
              />
            </label>
            <button type="submit" className="button" disabled={otherPortValue === null || isBusy}>
              Check
            </button>
            <button
              type="button"
              className="button"
              disabled={isBusy}
              onClick={() => void refresh()}
            >
              Refresh list
            </button>
          </form>
          {identity !== null && (
            <div className="identity" role="group" aria-label="Service identity">
              <dl>
                <dt>URL</dt>
                <dd>
                  <code>{identity.url}</code>
                </dd>
                <dt>Status</dt>
                <dd>
                  {identity.isHttp
                    ? identity.status
                    : `No HTTP response (${identity.error ?? "unknown"})`}
                </dd>
                <dt>Title</dt>
                <dd>{identity.title ?? "(none)"}</dd>
                <dt>Technology (inferred, not verified)</dt>
                <dd>{identity.inferredTechnologies.join(", ") || "unknown"}</dd>
              </dl>
              {identity.hasUnfollowedRedirect && (
                <Notice tone="warning">/ redirects to a location PGARD will not follow.</Notice>
              )}
              {identity.isHttp ? (
                <div className="confirm-row">
                  <p>Is this the current project's service?</p>
                  <button type="button" className="button primary" onClick={() => void confirm()}>
                    Yes, this is the project's service
                  </button>
                  <button type="button" className="button" onClick={() => setIdentity(null)}>
                    No
                  </button>
                </div>
              ) : (
                <Notice tone="warning">This port did not answer HTTP. Choose another port.</Notice>
              )}
            </div>
          )}
        </>
      )}
      {error && <Notice tone="error">{error}</Notice>}
    </Card>
  );
}
