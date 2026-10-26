import { en } from "../../i18n/en";
import type { Messages } from "../../i18n/types";

/** Only https links to github.com become clickable; anything else is shown as text. */
export function isGitHubUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.hostname === "github.com";
  } catch {
    return false;
  }
}

export function formatExpiry(expiresInSeconds: number, m: Messages = en): string {
  return m.deviceCode.expiry(Math.max(1, Math.round(expiresInSeconds / 60)));
}
