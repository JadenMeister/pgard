import type { AnalyzerOutput, ConfirmedWebTarget, Coverage, Finding } from "@pgard/findings";
import { checkCors } from "./checks/cors.js";
import { CookieFlagCollector } from "./checks/cookies.js";
import {
  checkDirectoryListing,
  checkEnvExposure,
  checkGitExposure,
  SENSITIVE_PATHS,
} from "./checks/exposure.js";
import { checkSecurityHeaders, checkVersionDisclosure } from "./checks/headers.js";
import {
  CORS_PROBE_ORIGIN,
  MAX_CRAWL_DEPTH,
  MAX_WEB_PAGES,
  REQUEST_TIMEOUT_MS,
  TOTAL_WEB_BUDGET_MS,
} from "./constants.js";
import { extractSameOriginLinks, isHtmlResponse } from "./html.js";
import {
  fetchLoopback,
  LoopbackRequestError,
  type LoopbackFetchResult,
  type LoopbackRequestOptions,
} from "./request.js";
import { WEB_RULE_IDS } from "./rules.js";
import { assertConfirmedWebTarget, InvalidTargetError } from "./target.js";

export interface WebScanProgress {
  pagesVisited: number;
  /** URL just requested (loopback, path only). */
  url: string;
}

export interface WebScanOptions {
  signal?: AbortSignal;
  onProgress?: (progress: WebScanProgress) => void;
  /** Overrides for tests only; values above the module limits are clamped. */
  limits?: Partial<WebScanLimits>;
  now?: () => number;
}

export interface WebScanLimits {
  maxPages: number;
  maxDepth: number;
  requestTimeoutMs: number;
  totalBudgetMs: number;
}

/** Shape `scan-core` receives by injection. */
export type WebScanner = (
  target: ConfirmedWebTarget,
  opts: WebScanOptions,
) => Promise<AnalyzerOutput>;

export const WEB_AREA_ANONYMOUS = "web:anonymous";
export const WEB_AREA_AUTHENTICATED = "web:authenticated";
export const AUTHENTICATED_NOT_AVAILABLE_NOTE =
  "authenticated browsing is not available in this MVP";
const HSTS_NOTE = "HSTS is not applicable to plain-http loopback and was not checked";
const GET_SIDE_EFFECT_NOTE = "GET requests can still change state in some apps";

function clampLimits(overrides: Partial<WebScanLimits> | undefined): WebScanLimits {
  return {
    maxPages: Math.min(overrides?.maxPages ?? MAX_WEB_PAGES, MAX_WEB_PAGES),
    maxDepth: Math.min(overrides?.maxDepth ?? MAX_CRAWL_DEPTH, MAX_CRAWL_DEPTH),
    requestTimeoutMs: Math.min(
      overrides?.requestTimeoutMs ?? REQUEST_TIMEOUT_MS,
      REQUEST_TIMEOUT_MS,
    ),
    totalBudgetMs: Math.min(overrides?.totalBudgetMs ?? TOTAL_WEB_BUDGET_MS, TOTAL_WEB_BUDGET_MS),
  };
}

function authenticatedCoverage(): Coverage {
  return {
    area: WEB_AREA_AUTHENTICATED,
    scope: "web",
    status: "not_selected",
    ruleIds: [],
    note: AUTHENTICATED_NOT_AVAILABLE_NOTE,
  };
}

function notTested(note: string): AnalyzerOutput {
  return {
    findings: [],
    coverage: [
      { area: WEB_AREA_ANONYMOUS, scope: "web", status: "not_tested", ruleIds: [], note },
      authenticatedCoverage(),
    ],
  };
}

/** Removes findings with the same id, keeping the first. */
function dedupeFindings(findings: Finding[]): Finding[] {
  const byId = new Map<string, Finding>();
  for (const finding of findings) if (!byId.has(finding.id)) byId.set(finding.id, finding);
  return [...byId.values()];
}

/**
 * Anonymous, read-only checks of a user-confirmed local HTTP service. Only GET requests are
 * sent, only to `127.0.0.1:<target.port>`, within fixed page/depth/time/body limits.
 */
export const scanLocalWeb: WebScanner = async (target, opts = {}) => {
  try {
    assertConfirmedWebTarget(target);
  } catch (error) {
    if (error instanceof InvalidTargetError) {
      return notTested(`Web target rejected: ${error.message}`);
    }
    throw error;
  }
  const limits = clampLimits(opts.limits);
  const now = opts.now ?? Date.now;
  const deadline = now() + limits.totalBudgetMs;
  const port = target.port;
  const gaps = new Set<string>();
  const findings: Finding[] = [];
  const cookies = new CookieFlagCollector();
  let pagesVisited = 0;
  let hasRootResponse = false;

  const request = async (
    path: string,
    extra: Pick<LoopbackRequestOptions, "headers"> = {},
  ): Promise<LoopbackFetchResult | null> => {
    const remaining = deadline - now();
    if (remaining <= 0) {
      gaps.add(`time budget of ${limits.totalBudgetMs / 1000}s reached`);
      return null;
    }
    if (opts.signal?.aborted === true) {
      gaps.add("cancelled by the user");
      return null;
    }
    try {
      const result = await fetchLoopback(port, path, {
        ...extra,
        timeoutMs: Math.min(limits.requestTimeoutMs, remaining),
        ...(opts.signal === undefined ? {} : { signal: opts.signal }),
      });
      opts.onProgress?.({ pagesVisited, url: result.response.url });
      if (result.redirectStop !== null) {
        gaps.add(
          result.redirectStop.reason === "off_target"
            ? "a redirect leaving 127.0.0.1 on this port was not followed"
            : result.redirectStop.reason === "unsafe_path"
              ? "a redirect to a logout/delete-like path was not followed"
              : "a redirect chain was stopped",
        );
      }
      cookies.addResponse(result.response.url, result.response.headers);
      return result;
    } catch (error) {
      if (error instanceof LoopbackRequestError) {
        gaps.add(
          error.code === "aborted"
            ? "cancelled by the user"
            : error.code === "timeout"
              ? "some requests timed out"
              : "some requests failed",
        );
        return null;
      }
      throw error;
    }
  };

  // Breadth-first crawl of same-origin HTML links from `/`.
  const visited = new Set<string>();
  let frontier: string[] = ["/"];
  for (let depth = 0; depth <= limits.maxDepth && frontier.length > 0; depth += 1) {
    const next: string[] = [];
    for (const path of frontier) {
      if (visited.has(path)) continue;
      if (pagesVisited >= limits.maxPages) {
        gaps.add(`page limit of ${limits.maxPages} reached`);
        break;
      }
      visited.add(path);
      pagesVisited += 1;
      const result = await request(path);
      if (result === null) continue;
      const { response } = result;
      const html = isHtmlResponse(response.headers) ? response.body.toString("utf8") : null;
      if (path === "/") {
        hasRootResponse = true;
        // A 3xx that was not followed is not the page users see; judging its headers would
        // produce misleading findings, so record the gap instead.
        const isUnfollowedRedirect =
          result.redirectStop !== null || (response.status >= 300 && response.status < 400);
        if (isUnfollowedRedirect) {
          gaps.add(
            "security headers were not checked because / redirected to a target PGARD does not follow",
          );
        } else {
          findings.push(...checkSecurityHeaders(response.url, response.headers));
        }
        findings.push(...checkVersionDisclosure(response.url, response.headers));
      }
      if (html !== null) {
        findings.push(...checkDirectoryListing(response, html));
        if (response.isBodyTruncated) gaps.add("some page bodies exceeded the size limit");
        if (depth < limits.maxDepth && result.redirectStop === null) {
          for (const link of extractSameOriginLinks(html, response.url, port)) {
            if (!visited.has(link)) next.push(link);
          }
        }
      }
    }
    if (depth === limits.maxDepth && next.length > 0)
      gaps.add(`crawl depth limit of ${limits.maxDepth} reached`);
    frontier = next;
  }

  if (!hasRootResponse) {
    const reason = [...gaps].join("; ") || "no response";
    return notTested(`The service did not answer GET / (${reason}).`);
  }

  const corsResult = await request("/", { headers: { origin: CORS_PROBE_ORIGIN } });
  if (corsResult !== null)
    findings.push(...checkCors(corsResult.response.url, corsResult.response.headers));

  const envResult = await request(SENSITIVE_PATHS.envFile);
  if (envResult !== null && envResult.redirectStop === null)
    findings.push(...checkEnvExposure(envResult.response));
  const gitResult = await request(SENSITIVE_PATHS.gitHead);
  if (gitResult !== null && gitResult.redirectStop === null)
    findings.push(...checkGitExposure(gitResult.response));

  findings.push(...cookies.findings);

  const isPartial = gaps.size > 0;
  const noteParts = [...gaps, HSTS_NOTE, GET_SIDE_EFFECT_NOTE];
  return {
    findings: dedupeFindings(findings),
    coverage: [
      {
        area: WEB_AREA_ANONYMOUS,
        scope: "web",
        status: isPartial ? "partial" : "completed",
        ruleIds: [...WEB_RULE_IDS],
        note: `${pagesVisited} page(s) checked. ${noteParts.join("; ")}.`,
      },
      authenticatedCoverage(),
    ],
  };
};
