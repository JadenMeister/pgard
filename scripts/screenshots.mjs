#!/usr/bin/env node
// Regenerates the preview screenshots in docs/assets/screenshots/ (README) and site/screenshots/
// (pgard.dev) from synthetic data. Run by hand, never in CI and not part of the package:
//
//   npm run build
//   npm run screenshots [-- panel report dashboard simple]     (default: all four)
//
// Needs Chrome (set CHROME=/path/to/chrome if it is not in a usual place). Headless only, and
// only file:// and 127.0.0.1 pages. No scan runs, nothing contacts GitHub, nothing is read from
// or written to the real PGARD store: the panel and the report are rendered from the fixture in
// scripts/screenshots/fixture.mjs, the dashboard and the simple screen come from the dev mock
// servers in apps/local-web/dev/.
import { spawn } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { localizeFindings } from "@pgard/findings";
import { launchChrome } from "./screenshots/chrome.mjs";
import { demoResult, ruleTexts } from "./screenshots/fixture.mjs";
import { optimizePng } from "./screenshots/png.mjs";
import { terminalPage } from "./screenshots/terminal-html.mjs";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const docsDir = join(root, "docs", "assets", "screenshots");
const siteDir = join(root, "site", "screenshots");
const work = mkdtempSync(join(tmpdir(), "pgard-shots-work-"));
const LANGS = { en: "en-US", ko: "ko-KR" };
const wanted = process.argv.slice(2).filter((arg) => !arg.startsWith("-"));
const wants = (name) => wanted.length === 0 || wanted.includes(name);
const children = [];

function save(name, png) {
  const optimized = optimizePng(png);
  mkdirSync(docsDir, { recursive: true });
  mkdirSync(siteDir, { recursive: true });
  writeFileSync(join(docsDir, name), optimized);
  copyFileSync(join(docsDir, name), join(siteDir, name));
  console.log(`${name}: ${Math.round(statSync(join(docsDir, name)).size / 1024)} KB`);
}

function startServer(script, args, pattern) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(root, script), ...args], {
      cwd: root,
      env: { ...process.env, PGARD_NO_STORE: "1" },
      stdio: ["ignore", "pipe", "inherit"],
    });
    children.push(child);
    let out = "";
    child.stdout.on("data", (data) => {
      out += data;
      const match = out.match(pattern);
      if (match) resolve(match[0]);
    });
    child.on("exit", (code) => reject(new Error(`${script} exited early (${code})`)));
  });
}

async function panels(chrome) {
  const { createPanelsState, reduce } = await import(
    pathToFileURL(join(root, "apps/cli/dist/ui/panels/reduce.js"))
  );
  const { renderFrame } = await import(
    pathToFileURL(join(root, "apps/cli/dist/ui/panels/layout.js"))
  );
  const { createStyle } = await import(
    pathToFileURL(join(root, "apps/cli/dist/ui/formatters/style.js"))
  );
  // Terminal size of the screenshots: 110 columns; the rows fit the content of each panel.
  const size = { columns: 110, rows: 20 };
  const options = { style: createStyle(true), unicode: true };
  for (const [lang, locale] of Object.entries(LANGS)) {
    const result = demoResult();
    // The CLI translates findings at render time; so does the screenshot.
    result.findings = localizeFindings(result.findings, ruleTexts, lang);
    const base = createPanelsState(result, lang, size, ruleTexts);
    const frames = {
      panel: { ...base, panel: "overview" },
      "panel-findings": { ...base, panel: "findings" },
    };
    for (const [name, state] of Object.entries(frames)) {
      const lines = renderFrame(state, size, options);
      const file = join(work, `${name}-${lang}.html`);
      writeFileSync(
        file,
        terminalPage(lines, { columns: size.columns, title: "pgard — acme/shop-demo" }),
      );
      await chrome.withPage({ width: 1300, height: 800, locale }, async (page) => {
        await page.goto(pathToFileURL(file).href);
        const box = await page.eval(
          "(() => { const r = document.querySelector('.window').getBoundingClientRect(); return [r.x, r.y, r.width, r.height]; })()",
        );
        const [x, y, width, height] = box;
        save(
          `${name}-${lang}.png`,
          await page.screenshot({ x: x - 28, y: y - 28, width: width + 56, height: height + 56 }),
        );
      });
    }
  }
}

async function report(chrome) {
  const { renderHtmlReport } = await import("@pgard/report");
  for (const [lang, locale] of Object.entries(LANGS)) {
    const file = join(work, `report-${lang}.html`);
    writeFileSync(file, renderHtmlReport(demoResult(), { lang, ruleTexts }));
    await chrome.withPage({ width: 1000, height: 1250, locale, dark: false }, async (page) => {
      await page.goto(pathToFileURL(file).href);
      // The preview shows summary, chart and the first findings: the coverage and standards
      // tables (the 2nd and 3rd heading) are left out so the findings fit in the picture.
      await page.eval(`(() => {
        const heads = [...document.querySelectorAll("h2")];
        for (let el = heads[1]; el && el !== heads[3]; el = el.nextElementSibling) el.style.display = "none";
      })()`);
      save(`report-${lang}.png`, await page.screenshot());
    });
  }
}

const SHOT_PORT = 4391;

async function dashboard(chrome) {
  await startServer(
    "apps/local-web/dev/mock-server.mjs",
    [String(SHOT_PORT)],
    /http:\/\/127\.0\.0\.1:\d+\/#token=\w+/,
  );
  const url = `http://127.0.0.1:${SHOT_PORT}/#token=mockmockmockmockmockmockmockmock`;
  for (const [lang, locale] of Object.entries(LANGS)) {
    await chrome.withPage({ width: 1280, height: 900, locale, dark: true }, async (page) => {
      await page.goto(url);
      await page.sleep(800);
      const click = (pattern) =>
        page.eval(
          `[...document.querySelectorAll("button,[role=tab]")].find((b) => ${pattern}.test(b.textContent))?.click()`,
        );
      await click("/understand|이해했습니다/");
      await page.sleep(800);
      await click("/^(Run scan|검사 실행)$/");
      await page.sleep(1500);
      await click("/^(Overview|개요)$/");
      await page.sleep(800);
      save(`dashboard-${lang}.png`, await page.screenshot());
    });
  }
}

// The `pgard web` screen: the real server in picker mode with a stand-in inspector (see the
// header of the preview server). Its link works in one tab only, so each language starts one.
// Only the first screen is shown: checking a folder needs the real file system.
async function simple(chrome) {
  let port = SHOT_PORT + 1;
  for (const [lang, locale] of Object.entries(LANGS)) {
    const url = await startServer(
      "apps/local-web/dev/picker-preview-server.mjs",
      [String(port), "simple"],
      /http:\/\/127\.0\.0\.1:\d+\/#token=\w+/,
    );
    port += 1;
    await chrome.withPage({ width: 1100, height: 680, locale, dark: true }, async (page) => {
      await page.goto(url);
      await page.sleep(800);
      await page.eval(
        `[...document.querySelectorAll("button")].find((b) => /understand|이해했습니다/.test(b.textContent))?.click()`,
      );
      await page.sleep(800);
      save(`web-${lang}.png`, await page.screenshot());
    });
  }
}

async function main() {
  const chrome = await launchChrome();
  try {
    if (wants("panel")) await panels(chrome);
    if (wants("report")) await report(chrome);
    if (wants("dashboard")) await dashboard(chrome);
    if (wants("simple")) await simple(chrome);
  } finally {
    await chrome.close();
    for (const child of children) child.kill();
    rmSync(work, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
