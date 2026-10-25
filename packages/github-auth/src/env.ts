export const GITHUB_APP_CLIENT_ID_ENV = "PGARD_GITHUB_APP_CLIENT_ID";
export const GITHUB_APP_SLUG_ENV = "PGARD_GITHUB_APP_SLUG";

/**
 * Client id of the official PGARD GitHub App. It is public by design: the App signs users in
 * with the device flow, which needs no client secret, and PGARD has no client secret anywhere.
 */
export const DEFAULT_GITHUB_APP_CLIENT_ID = "Iv23liKDf0mhnPl2c7zj";

/**
 * Slug of the official PGARD GitHub App (`https://github.com/apps/pgard-jadenmeister`). Public,
 * like the client id; it is only used to link to the App's install page.
 */
export const DEFAULT_GITHUB_APP_SLUG = "pgard-jadenmeister";

/**
 * Fixed reason shown when the override is set but malformed. The value itself is never echoed.
 */
export const INVALID_CLIENT_ID_OVERRIDE_MESSAGE = `${GITHUB_APP_CLIENT_ID_ENV} is set but is not a valid client id; unset it to use the built-in PGARD App.`;

/** Fixed reason shown when the slug override is set but malformed. The value is never echoed. */
export const INVALID_APP_SLUG_OVERRIDE_MESSAGE = `${GITHUB_APP_SLUG_ENV} is set but is not a valid GitHub App slug (lowercase letters, digits and "-"); fix or unset it.`;

/**
 * Said when the client id is overridden without a slug: PGARD cannot know which App page to open,
 * so there is no install link.
 */
export const GUIDED_INSTALL_NEEDS_SLUG_MESSAGE = `Set ${GITHUB_APP_SLUG_ENV} to enable the guided install.`;

/** GitHub App client ids are public identifiers such as `Iv23li...`. */
const CLIENT_ID_PATTERN = /^[A-Za-z0-9._-]{1,100}$/;
/** GitHub App slugs as they appear in `https://github.com/apps/<slug>`. */
export const APP_SLUG_PATTERN = /^[a-z0-9-]{1,100}$/;

/**
 * Where the client id came from: the built-in PGARD App, the env override, or an override that
 * is set but malformed (then there is no client id and GitHub identity is unverifiable).
 */
export type GitHubAppClientIdSource = "default" | "env" | "invalid";

export type ResolvedGitHubAppClientId =
  | {
      clientId: string;
      /**
       * Slug for the App's install page: `PGARD_GITHUB_APP_SLUG`, else the built-in slug when the
       * built-in client id is used, else `null` (an overridden client id without a slug).
       */
      slug: string | null;
      source: "default" | "env";
    }
  | {
      clientId: null;
      slug: null;
      source: "invalid";
      /** Fixed text naming which override is malformed. */
      message: string;
    };

/**
 * Resolves the GitHub App used for the device flow and for the guided install link. This is the
 * only place that reads `PGARD_GITHUB_APP_CLIENT_ID` and `PGARD_GITHUB_APP_SLUG`, which a fork or
 * a self-registered App sets to override the built-in PGARD App. Unset, empty or whitespace-only
 * counts as unset.
 *
 * A malformed override (client id or slug) resolves to `source: "invalid"` and no client id. It
 * never falls back to the built-in App: the operator asked for another App, and proving owner
 * approval against a different App than the one configured would be unclear evidence, so callers
 * block instead.
 */
export function resolveGitHubAppClientId(
  env: Readonly<Record<string, string | undefined>>,
): ResolvedGitHubAppClientId {
  const value = env[GITHUB_APP_CLIENT_ID_ENV]?.trim();
  const slugValue = env[GITHUB_APP_SLUG_ENV]?.trim();
  if (value && !CLIENT_ID_PATTERN.test(value)) {
    return {
      clientId: null,
      slug: null,
      source: "invalid",
      message: INVALID_CLIENT_ID_OVERRIDE_MESSAGE,
    };
  }
  if (slugValue && !APP_SLUG_PATTERN.test(slugValue)) {
    return {
      clientId: null,
      slug: null,
      source: "invalid",
      message: INVALID_APP_SLUG_OVERRIDE_MESSAGE,
    };
  }
  if (!value) {
    return {
      clientId: DEFAULT_GITHUB_APP_CLIENT_ID,
      slug: slugValue || DEFAULT_GITHUB_APP_SLUG,
      source: "default",
    };
  }
  return { clientId: value, slug: slugValue || null, source: "env" };
}
