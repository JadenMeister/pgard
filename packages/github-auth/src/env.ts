export const GITHUB_APP_CLIENT_ID_ENV = "PGARD_GITHUB_APP_CLIENT_ID";

/**
 * Client id of the official PGARD GitHub App. It is public by design: the App signs users in
 * with the device flow, which needs no client secret, and PGARD has no client secret anywhere.
 */
export const DEFAULT_GITHUB_APP_CLIENT_ID = "Iv23liKDf0mhnPl2c7zj";

/**
 * Fixed reason shown when the override is set but malformed. The value itself is never echoed.
 */
export const INVALID_CLIENT_ID_OVERRIDE_MESSAGE = `${GITHUB_APP_CLIENT_ID_ENV} is set but is not a valid client id; unset it to use the built-in PGARD App.`;

/** GitHub App client ids are public identifiers such as `Iv23li...`. */
const CLIENT_ID_PATTERN = /^[A-Za-z0-9._-]{1,100}$/;

/**
 * Where the client id came from: the built-in PGARD App, the env override, or an override that
 * is set but malformed (then there is no client id and GitHub identity is unverifiable).
 */
export type GitHubAppClientIdSource = "default" | "env" | "invalid";

export type ResolvedGitHubAppClientId =
  { clientId: string; source: "default" | "env" } | { clientId: null; source: "invalid" };

/**
 * Resolves the GitHub App client id used for the device flow. This is the only place that reads
 * `PGARD_GITHUB_APP_CLIENT_ID`, which a fork or a self-registered App sets to override the
 * built-in PGARD App. Unset, empty or whitespace-only counts as unset.
 *
 * A malformed override resolves to `source: "invalid"` and no client id. It never falls back to
 * the built-in App: the operator asked for another App, and proving owner approval against a
 * different App than the one configured would be unclear evidence, so callers block instead.
 */
export function resolveGitHubAppClientId(
  env: Readonly<Record<string, string | undefined>>,
): ResolvedGitHubAppClientId {
  const value = env[GITHUB_APP_CLIENT_ID_ENV]?.trim();
  if (!value) return { clientId: DEFAULT_GITHUB_APP_CLIENT_ID, source: "default" };
  if (!CLIENT_ID_PATTERN.test(value)) return { clientId: null, source: "invalid" };
  return { clientId: value, source: "env" };
}
