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
    // Give the browser a moment to start reading the blob before it is released.
    setTimeout(() => environment.revokeObjectUrl(url), 0);
  }
}
