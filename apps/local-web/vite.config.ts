import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

const root = fileURLToPath(new URL("./src/client", import.meta.url));
const outDir = fileURLToPath(new URL("./dist/client", import.meta.url));

// The browser bundle contains only the React UI and pure helpers. It must never pull in Node
// APIs, the scan engine or GitHub auth code; see src/client/api/client.ts for the only boundary.
export default defineConfig({
  root,
  base: "./",
  resolve: { conditions: ["source", "browser", "import", "module", "default"] },
  oxc: { jsx: { runtime: "automatic" } },
  build: {
    outDir,
    emptyOutDir: true,
    sourcemap: false,
    // Everything is served from 127.0.0.1 with a strict CSP; no inline scripts.
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
  },
});
