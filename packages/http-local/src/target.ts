import type { ConfirmedWebTarget } from "@pgard/findings";
import { LOOPBACK_IPV4, LOOPBACK_IPV6 } from "./constants.js";

export class InvalidTargetError extends Error {
  readonly code = "invalid_target";
  constructor(message: string) {
    super(message);
    this.name = "InvalidTargetError";
  }
}

const PORT_PATTERN = /^[0-9]{1,5}$/;

/** True for integer ports 1-65535. */
export function isValidPort(port: unknown): port is number {
  return typeof port === "number" && Number.isInteger(port) && port >= 1 && port <= 65535;
}

/**
 * Parses a user-supplied port string. Only plain decimal digits are accepted
 * (no signs, no hex, no whitespace, no host:port).
 */
export function parsePort(value: string): number {
  const port = PORT_PATTERN.test(value) ? Number(value) : Number.NaN;
  if (!isValidPort(port)) {
    throw new InvalidTargetError(`Invalid port "${value}": expected an integer from 1 to 65535.`);
  }
  return port;
}

export function buildLoopbackOrigin(port: number): string {
  if (!isValidPort(port)) {
    throw new InvalidTargetError(`Invalid port ${String(port)}.`);
  }
  return `http://${LOOPBACK_IPV4}:${port}`;
}

export interface LoopbackUrlOptions {
  /** Port every URL must use. */
  port: number;
  /** Allow `[::1]` in addition to `127.0.0.1`. Off by default. */
  isIpv6LoopbackAllowed?: boolean;
}

/**
 * Returns the parsed URL when it is plain `http:` to the numeric loopback address on the
 * expected port, otherwise `null`. Hostnames (including `localhost`), other IPs, credentials,
 * other schemes and other ports are all rejected.
 */
export function parseAllowedLoopbackUrl(
  raw: string,
  base: string | URL | undefined,
  options: LoopbackUrlOptions,
): URL | null {
  let url: URL;
  try {
    url = base === undefined ? new URL(raw) : new URL(raw, base);
  } catch {
    return null;
  }
  if (url.protocol !== "http:") return null;
  if (url.username !== "" || url.password !== "") return null;
  const isIpv4Loopback = url.hostname === LOOPBACK_IPV4;
  const isIpv6Loopback =
    options.isIpv6LoopbackAllowed === true && url.hostname === `[${LOOPBACK_IPV6}]`;
  if (!isIpv4Loopback && !isIpv6Loopback) return null;
  const effectivePort = url.port === "" ? 80 : Number(url.port);
  if (effectivePort !== options.port) return null;
  return url;
}

/**
 * Re-validates a `ConfirmedWebTarget` at the trust boundary. Anything other than an explicit
 * user confirmation for `http://127.0.0.1:<port>` is refused.
 */
export function assertConfirmedWebTarget(target: ConfirmedWebTarget): void {
  if (target === null || typeof target !== "object") {
    throw new InvalidTargetError("Web target is missing.");
  }
  if (target.confirmedByUser !== true) {
    throw new InvalidTargetError("Web target was not confirmed by the user.");
  }
  if (!isValidPort(target.port)) {
    throw new InvalidTargetError("Web target port is invalid.");
  }
  if (target.origin !== buildLoopbackOrigin(target.port)) {
    throw new InvalidTargetError("Web target origin must be http://127.0.0.1:<port>.");
  }
}
