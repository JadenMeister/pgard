import { readdir, readFile } from "node:fs/promises";
import path from "node:path";

const CONTENT_TYPES: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".ico": "image/x-icon",
  ".woff2": "font/woff2",
};

export interface StaticAsset {
  body: Buffer;
  contentType: string;
}

/**
 * Loads the built UI into memory once at startup. Requests are answered only from this fixed
 * map (exact URL match), so no request path is ever joined onto the file system.
 */
export async function loadStaticAssets(clientDir: string): Promise<Map<string, StaticAsset>> {
  const assets = new Map<string, StaticAsset>();
  const walk = async (directory: string, urlPrefix: string): Promise<void> => {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const fullPath = path.join(directory, entry.name);
      const url = `${urlPrefix}${entry.name}`;
      if (entry.isDirectory()) {
        await walk(fullPath, `${url}/`);
      } else if (entry.isFile()) {
        const contentType = CONTENT_TYPES[path.extname(entry.name).toLowerCase()];
        if (contentType !== undefined) {
          assets.set(url, { body: await readFile(fullPath), contentType });
        }
      }
    }
  };
  await walk(clientDir, "/");
  const index = assets.get("/index.html");
  if (index !== undefined) assets.set("/", index);
  return assets;
}
