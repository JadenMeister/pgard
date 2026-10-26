import type { ReactNode } from "react";

/** The only sites a standards link may point to: the official pages of the bundled standards. */
const OFFICIAL_HOSTS: ReadonlySet<string> = new Set([
  "top10.owasp.org",
  "cwe.mitre.org",
  "cmu-sei.github.io",
]);

/** True for an `https:` URL on an official standards host (no credentials, no other scheme). */
export function isOfficialStandardsUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return (
      parsed.protocol === "https:" &&
      parsed.username === "" &&
      parsed.password === "" &&
      OFFICIAL_HOSTS.has(parsed.hostname)
    );
  } catch {
    return false;
  }
}

/**
 * Link to an official page of a standard. Opens in a new tab without opener or referrer; the
 * dashboard's CSP does not restrict navigation. Anything that is not an official https URL is
 * shown as plain text, never as a link.
 */
export function ExternalLink({
  url,
  children,
  hint,
}: {
  url: string;
  children: ReactNode;
  /** Screen-reader hint that the link leaves the dashboard. */
  hint?: string;
}) {
  if (!isOfficialStandardsUrl(url)) return <span>{children}</span>;
  return (
    <a href={url} target="_blank" rel="noopener noreferrer" title={hint}>
      {children}
    </a>
  );
}
