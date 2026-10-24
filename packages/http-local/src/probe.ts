import type { ConfirmedWebTarget } from "@pgard/findings";
import { PROBE_TIMEOUT_MS } from "./constants.js";
import { extractTitle, inferTechnologies, isHtmlResponse } from "./html.js";
import { fetchLoopback, LoopbackRequestError, type RedirectStopReason } from "./request.js";
import { buildLoopbackOrigin, InvalidTargetError, isValidPort } from "./target.js";

/** Identity of a local HTTP service, shown to the user before they confirm it. */
export interface ServiceIdentity {
  port: number;
  url: string;
  /** `null` when the port did not answer HTTP. */
  status: number | null;
  title: string | null;
  /** Guesses from headers/HTML; display as "inferred". */
  inferredTechnologies: string[];
  isHttp: boolean;
  /** Present when `/` redirected somewhere PGARD will not follow. */
  redirectStop: RedirectStopReason | null;
  error: string | null;
}

export interface ProbeOptions {
  timeoutMs?: number;
  signal?: AbortSignal;
}

/** GET `/` on `127.0.0.1:<port>` and describe what answered. Never throws for network errors. */
export async function probeLocalService(
  port: number,
  options: ProbeOptions = {},
): Promise<ServiceIdentity> {
  const url = `${buildLoopbackOrigin(port)}/`;
  try {
    const { response, redirectStop } = await fetchLoopback(port, "/", {
      timeoutMs: options.timeoutMs ?? PROBE_TIMEOUT_MS,
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    const html = isHtmlResponse(response.headers) ? response.body.toString("utf8") : null;
    return {
      port,
      url,
      status: response.status,
      title: html === null ? null : extractTitle(html),
      inferredTechnologies: inferTechnologies(response.headers, html),
      isHttp: true,
      redirectStop: redirectStop?.reason ?? null,
      error: null,
    };
  } catch (error) {
    const message =
      error instanceof LoopbackRequestError
        ? error.code === "timeout"
          ? "No HTTP response before the timeout."
          : error.code === "aborted"
            ? "Cancelled."
            : "Connection failed or the port did not speak HTTP."
        : "Unexpected error while probing.";
    return {
      port,
      url,
      status: null,
      title: null,
      inferredTechnologies: [],
      isHttp: false,
      redirectStop: null,
      error: message,
    };
  }
}

/**
 * Builds the `ConfirmedWebTarget` only when the user explicitly answered yes after seeing the
 * identity. `isConfirmedByUser` must be the literal `true` from a `y` answer.
 */
export function createConfirmedWebTarget(
  identity: ServiceIdentity,
  isConfirmedByUser: boolean,
): ConfirmedWebTarget {
  if (isConfirmedByUser !== true) {
    throw new InvalidTargetError("The web target was not confirmed by the user.");
  }
  if (!isValidPort(identity.port) || !identity.isHttp) {
    throw new InvalidTargetError("Only a port that answered HTTP can be confirmed.");
  }
  return {
    port: identity.port,
    origin: buildLoopbackOrigin(identity.port),
    title: identity.title,
    confirmedByUser: true,
  };
}

/** Parses a y/N answer. Only `y`/`yes` (any case) count as yes; empty input means no. */
export function isExplicitYes(answer: string): boolean {
  return /^(y|yes)$/i.test(answer.trim());
}
