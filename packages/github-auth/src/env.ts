export const GITHUB_APP_CLIENT_ID_ENV = "PGARD_GITHUB_APP_CLIENT_ID";

/** GitHub App client ids are public identifiers such as `Iv23li...`. */
const CLIENT_ID_PATTERN = /^[A-Za-z0-9._-]{1,100}$/;

/**
 * Reads the GitHub App client id used for the device flow. Returns `null` when it is unset
 * or malformed; callers must then treat GitHub identity as unverifiable.
 */
export function readGitHubAppClientId(
  env: Readonly<Record<string, string | undefined>>,
): string | null {
  const value = env[GITHUB_APP_CLIENT_ID_ENV]?.trim();
  if (!value || !CLIENT_ID_PATTERN.test(value)) {
    return null;
  }
  return value;
}
