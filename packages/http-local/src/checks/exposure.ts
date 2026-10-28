import type { Finding } from "@pgard/findings";
import { buildWebFinding } from "../build-finding.js";
import { isHtmlResponse } from "../html.js";
import type { LoopbackResponse } from "../request.js";
import { WEB_RULES } from "../rules.js";

/** Paths requested once per scan with GET. Only presence is reported, never body content. */
export const SENSITIVE_PATHS = {
  envFile: "/.env",
  gitHead: "/.git/HEAD",
} as const;

// Leading blanks stay on the line (`\s*` ran across empty lines and rescanned them per line).
const ENV_ASSIGNMENT = /^[^\S\n\r\u2028\u2029]*(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*\s*=/gm;

function looksLikeHtml(response: LoopbackResponse, text: string): boolean {
  return isHtmlResponse(response.headers) || /^\s*</.test(text);
}

/**
 * `.env` counts as exposed only for a 200 non-HTML body with KEY=VALUE lines, so SPA fallbacks
 * that return index.html for every path do not trigger it. The body is discarded after counting.
 */
export function checkEnvExposure(response: LoopbackResponse): Finding[] {
  if (response.status !== 200) return [];
  const text = response.body.toString("utf8");
  if (looksLikeHtml(response, text)) return [];
  const assignmentCount = text.match(ENV_ASSIGNMENT)?.length ?? 0;
  if (assignmentCount === 0) return [];
  return [
    buildWebFinding(
      WEB_RULES.exposedEnvFile,
      response.url,
      "env",
      `GET ${SENSITIVE_PATHS.envFile} returned 200 with ${assignmentCount} KEY=VALUE line(s); values were not recorded.`,
    ),
  ];
}

/** `.git/HEAD` counts as exposed for a 200 body that is a ref line or a commit id. */
export function checkGitExposure(response: LoopbackResponse): Finding[] {
  if (response.status !== 200) return [];
  const text = response.body.toString("utf8");
  if (looksLikeHtml(response, text)) return [];
  if (!/^\s*(ref:\s*refs\/|[0-9a-f]{40}\s*$|[0-9a-f]{64}\s*$)/.test(text)) return [];
  return [
    buildWebFinding(
      WEB_RULES.exposedGitDirectory,
      response.url,
      "git-head",
      `GET ${SENSITIVE_PATHS.gitHead} returned 200 with Git HEAD content; content was not recorded.`,
    ),
  ];
}

/** Detects auto-generated directory index pages. */
export function checkDirectoryListing(response: LoopbackResponse, html: string): Finding[] {
  if (response.status !== 200) return [];
  if (!/<title\b[^>]*>\s*(index of\s*\/|directory listing for\s*\/)/i.test(html)) return [];
  return [
    buildWebFinding(
      WEB_RULES.directoryListing,
      response.url,
      "listing",
      "The page is an automatically generated directory index.",
    ),
  ];
}
