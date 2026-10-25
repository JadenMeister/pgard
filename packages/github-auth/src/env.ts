export const GITHUB_APP_CLIENT_ID_ENV = "PGARD_GITHUB_APP_CLIENT_ID";

/**
 * Client id of the official PGARD GitHub App. It is public by design: the App signs users in
 * with the device flow, which needs no client secret, and PGARD has no client secret anywhere.
 */
export const DEFAULT_GITHUB_APP_CLIENT_ID = "Iv23liKDf0mhnPl2c7zj";

/** GitHub App client ids are public identifiers such as `Iv23li...`. */
const CLIENT_ID_PATTERN = /^[A-Za-z0-9._-]{1,100}$/;

/** Where the client id came from: the built-in PGARD App, or the env override. */
export type GitHubAppClientIdSource = "default" | "env";

export interface ResolvedGitHubAppClientId {
  clientId: string;
  source: GitHubAppClientIdSource;
  /**
   * `true` when `PGARD_GITHUB_APP_CLIENT_ID` was set to something that is not a client id (for
   * example `a b`): it was ignored and the built-in App is used. `pgard doctor` reports it.
   */
  isOverrideIgnored: boolean;
}

/**
 * Resolves the GitHub App client id used for the device flow. This is the only place that reads
 * `PGARD_GITHUB_APP_CLIENT_ID`, which a fork or a self-registered App sets to override the
 * built-in PGARD App. Unset, empty or whitespace-only counts as unset; a malformed value is
 * ignored (and flagged) rather than sent to GitHub.
 */
export function resolveGitHubAppClientId(
  env: Readonly<Record<string, string | undefined>>,
): ResolvedGitHubAppClientId {
  const value = env[GITHUB_APP_CLIENT_ID_ENV]?.trim();
  if (value && CLIENT_ID_PATTERN.test(value)) {
    return { clientId: value, source: "env", isOverrideIgnored: false };
  }
  return {
    clientId: DEFAULT_GITHUB_APP_CLIENT_ID,
    source: "default",
    isOverrideIgnored: Boolean(value),
  };
}
