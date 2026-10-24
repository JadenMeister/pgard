import type http from "node:http";
import type { Finding } from "@pgard/findings";
import { buildWebFinding } from "../build-finding.js";
import { sanitizeDisplayText } from "../display-text.js";
import { WEB_RULES } from "../rules.js";

export interface CookieAttributes {
  /** Cookie name only. The value is never kept. */
  name: string;
  isHttpOnly: boolean;
  isSecure: boolean;
  hasSameSite: boolean;
}

/** Parses one Set-Cookie header into its name and flags, discarding the value. */
export function parseSetCookie(header: string): CookieAttributes | null {
  const [pair, ...attributes] = header.split(";");
  if (pair === undefined) return null;
  const separator = pair.indexOf("=");
  if (separator <= 0) return null;
  const name = sanitizeDisplayText(pair.slice(0, separator), 60);
  if (name === "") return null;
  const flags = attributes.map((attribute) => attribute.trim().toLowerCase());
  return {
    name,
    isHttpOnly: flags.includes("httponly"),
    isSecure: flags.includes("secure"),
    hasSameSite: flags.some((flag) => /^samesite\s*=\s*(lax|strict|none)$/.test(flag)),
  };
}

/**
 * Cookie flag checks across responses. Each (rule, cookie name) is reported once, at the first
 * URL that set it. Evidence names the cookie but never includes its value.
 */
export class CookieFlagCollector {
  readonly #seen = new Set<string>();
  readonly #findings: Finding[] = [];

  addResponse(url: string, headers: http.IncomingHttpHeaders): void {
    for (const header of headers["set-cookie"] ?? []) {
      const cookie = parseSetCookie(header);
      if (cookie === null) continue;
      if (!cookie.isHttpOnly)
        this.#add(WEB_RULES.cookieWithoutHttpOnly, url, cookie.name, "HttpOnly");
      if (!cookie.hasSameSite)
        this.#add(WEB_RULES.cookieWithoutSameSite, url, cookie.name, "SameSite");
      if (!cookie.isSecure) this.#add(WEB_RULES.cookieWithoutSecure, url, cookie.name, "Secure");
    }
  }

  get findings(): Finding[] {
    return [...this.#findings];
  }

  #add(
    rule: (typeof WEB_RULES)[keyof typeof WEB_RULES],
    url: string,
    name: string,
    flag: string,
  ): void {
    const key = `${rule.id}\n${name}`;
    if (this.#seen.has(key)) return;
    this.#seen.add(key);
    this.#findings.push(
      buildWebFinding(
        rule,
        url,
        `cookie:${name}`,
        `Set-Cookie for "${name}" lacks ${flag} (value not recorded).`,
      ),
    );
  }
}
