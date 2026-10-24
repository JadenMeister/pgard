import type http from "node:http";
import { sanitizeDisplayText } from "./display-text.js";
import { parseAllowedLoopbackUrl } from "./target.js";

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
};

export function decodeHtmlEntities(value: string): string {
  return value.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, (match, entity: string) => {
    if (entity.startsWith("#x") || entity.startsWith("#X")) {
      const code = Number.parseInt(entity.slice(2), 16);
      return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : match;
    }
    if (entity.startsWith("#")) {
      const code = Number.parseInt(entity.slice(1), 10);
      return Number.isFinite(code) && code <= 0x10ffff ? String.fromCodePoint(code) : match;
    }
    return NAMED_ENTITIES[entity.toLowerCase()] ?? match;
  });
}

export function isHtmlResponse(headers: http.IncomingHttpHeaders): boolean {
  const contentType = headers["content-type"];
  return (
    typeof contentType === "string" && /\btext\/html\b|application\/xhtml\+xml/i.test(contentType)
  );
}

/** Extracts a display-safe `<title>` or `null`. */
export function extractTitle(html: string): string | null {
  const match = /<title\b[^>]*>([\s\S]*?)<\/title\s*>/i.exec(html);
  if (match === null || match[1] === undefined) return null;
  const title = sanitizeDisplayText(decodeHtmlEntities(match[1]));
  return title === "" ? null : title;
}

/** Path segments that commonly trigger state changes even over GET; never followed by the crawler. */
const UNSAFE_LINK_PATTERN =
  /(^|[/_.-])(log-?out|sign-?out|logoff|delete|remove|destroy|unsubscribe|reset|revoke|disable|deactivate)([/_.?-]|$)/i;

export function isUnsafeLinkPath(pathname: string): boolean {
  return UNSAFE_LINK_PATTERN.test(pathname);
}

/**
 * Same-origin `<a href>` links of an HTML page, normalized to path only (query and fragment are
 * dropped so tokens in links are neither requested nor reported). Links that look like
 * state-changing actions are skipped.
 */
export function extractSameOriginLinks(html: string, pageUrl: string, port: number): string[] {
  const paths = new Set<string>();
  const anchorPattern = /<a\b[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/gi;
  for (const match of html.matchAll(anchorPattern)) {
    const raw = decodeHtmlEntities((match[1] ?? match[2] ?? match[3] ?? "").trim());
    if (raw === "" || raw.startsWith("#")) continue;
    const url = parseAllowedLoopbackUrl(raw, pageUrl, { port });
    if (url === null) continue;
    if (isUnsafeLinkPath(url.pathname)) continue;
    paths.add(url.pathname);
  }
  return [...paths];
}

/**
 * Technology hints from headers and HTML markers. These are guesses ("inferred"), never proof,
 * and the port number is never used as a hint.
 */
export function inferTechnologies(
  headers: http.IncomingHttpHeaders,
  html: string | null,
): string[] {
  const hints = new Set<string>();
  for (const name of ["server", "x-powered-by"] as const) {
    const value = headers[name];
    if (typeof value === "string" && value.trim() !== "") {
      hints.add(sanitizeDisplayText(value, 60));
    }
  }
  if (html !== null) {
    const generator =
      /<meta\b[^>]*name\s*=\s*["']generator["'][^>]*content\s*=\s*["']([^"']+)["']/i.exec(html);
    if (generator?.[1] !== undefined)
      hints.add(sanitizeDisplayText(decodeHtmlEntities(generator[1]), 60));
    if (/\/_next\//.test(html)) hints.add("Next.js");
    if (/\/_nuxt\//.test(html)) hints.add("Nuxt");
    if (/\/@vite\/client/.test(html)) hints.add("Vite dev server");
    if (/data-reactroot|__REACT_DEVTOOLS|react-refresh/i.test(html)) hints.add("React");
    if (/data-v-app|__VUE__/i.test(html)) hints.add("Vue");
  }
  return [...hints];
}
