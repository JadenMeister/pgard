/** How long the object URL stays valid after the click. */
export const REVOKE_DELAY_MS = 30_000;

/** What `triggerDownload` needs from the page; tests pass fakes. */
export interface DownloadEnvironment {
  createObjectUrl: (blob: Blob) => string;
  revokeObjectUrl: (url: string) => void;
  createAnchor: () => {
    href: string;
    download: string;
    rel: string;
    click: () => void;
    remove: () => void;
  };
  appendAnchor: (anchor: unknown) => void;
}

export function browserDownloadEnvironment(): DownloadEnvironment {
  return {
    createObjectUrl: (blob) => URL.createObjectURL(blob),
    revokeObjectUrl: (url) => URL.revokeObjectURL(url),
    createAnchor: () => document.createElement("a"),
    appendAnchor: (anchor) => document.body.appendChild(anchor as Node),
  };
}

/**
 * Saves `blob` through the browser's normal download: a temporary `<a download>` pointing at an
 * object URL, clicked once and removed, then the URL is revoked. Works under the dashboard's CSP.
 */
export function triggerDownload(
  blob: Blob,
  filename: string,
  environment: DownloadEnvironment = browserDownloadEnvironment(),
): void {
  const url = environment.createObjectUrl(blob);
  const anchor = environment.createAnchor();
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  environment.appendAnchor(anchor);
  try {
    anchor.click();
  } finally {
    anchor.remove();
    // Safari and Firefox read the blob after the click returns; release it only after a delay.
    setTimeout(() => environment.revokeObjectUrl(url), REVOKE_DELAY_MS);
  }
}
