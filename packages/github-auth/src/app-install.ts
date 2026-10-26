import { GITHUB_OAUTH_BASE_URL } from "./device-flow.js";
import { APP_SLUG_PATTERN } from "./env.js";

/** The only origin PGARD ever links to or opens: GitHub.com. GHES is not supported here. */
export const GITHUB_WEB_ORIGIN = "https://github.com";

export interface AppInstallUrlInput {
  /** Validated App slug (`resolveGitHubAppClientId(env).slug`). */
  slug: string;
  /** Numeric id GitHub reported for the account that owns the repository. */
  targetId: number;
  /**
   * Numeric id GitHub reported for the repository. Omitted (not invalid) when the repository is
   * not visible to the signed-in user yet, so the link preselects only the account.
   */
  repositoryId?: number;
  /** Web origin of the GitHub host; anything but `https://github.com` gets no link. */
  webBaseUrl?: string;
}

function isPositiveId(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}

/**
 * The GitHub App install page, preselected for the owner account and this repository:
 *
 * `https://github.com/apps/<slug>/installations/new/permissions?suggested_target_id=<account id>&repository_ids[]=<repo id>`
 *
 * GitHub documents these query parameters in "Migrating OAuth apps to GitHub Apps"
 * (`suggested_target_id` is required, `repository_ids[]` preselects repositories). The user still
 * chooses "Only select repositories" or "All repositories" and clicks Install on GitHub; PGARD
 * never installs anything itself.
 *
 * Built only from the validated slug and numeric ids returned by GitHub, with URL APIs; no remote
 * string is interpolated. Returns `null` for a non-github.com host, a malformed slug or an id that
 * is not a positive integer.
 */
export function buildAppInstallUrl(input: AppInstallUrlInput): string | null {
  const base = input.webBaseUrl ?? GITHUB_OAUTH_BASE_URL;
  if (base !== GITHUB_WEB_ORIGIN) return null;
  if (!APP_SLUG_PATTERN.test(input.slug)) return null;
  if (!isPositiveId(input.targetId)) return null;
  if (input.repositoryId !== undefined && !isPositiveId(input.repositoryId)) return null;
  const url = new URL(`/apps/${input.slug}/installations/new/permissions`, GITHUB_WEB_ORIGIN);
  url.searchParams.set("suggested_target_id", String(input.targetId));
  if (input.repositoryId !== undefined) {
    url.searchParams.append("repository_ids[]", String(input.repositoryId));
  }
  const built = url.toString();
  return isOpenableGitHubUrl(built) ? built : null;
}

/**
 * True only for an `https://github.com/...` URL without credentials or a port, so nothing else
 * can ever be handed to the system browser opener or rendered as an install link.
 */
export function isOpenableGitHubUrl(value: string): boolean {
  if (typeof value !== "string" || !value.startsWith(`${GITHUB_WEB_ORIGIN}/`)) return false;
  if (value.length > 2048 || /[\s"'<>`\\^|{}]/.test(value)) return false;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return (
    url.protocol === "https:" &&
    url.hostname === "github.com" &&
    url.port === "" &&
    url.username === "" &&
    url.password === ""
  );
}
