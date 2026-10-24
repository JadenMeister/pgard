/** Only https links to github.com become clickable; anything else is shown as text. */
export function isGitHubUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.hostname === "github.com";
  } catch {
    return false;
  }
}

export function formatExpiry(expiresInSeconds: number): string {
  return `Expires in about ${Math.max(1, Math.round(expiresInSeconds / 60))} min.`;
}
