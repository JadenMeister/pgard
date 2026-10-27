// Pty smoke test for the CLI panel view. Runs `run-panels.mjs` (the built CLI with a fixture scan
// result, no GitHub, no network) inside a real pseudo terminal (ConPTY on Windows), types scripted
// keys and asserts on the terminal output. Meant for .github/workflows/windows-tty-smoke.yml, but
// platform-agnostic so it can be tried on macOS or Linux first.
//
//   node scripts/windows-pty-smoke/smoke.mjs --node-pty <dir that has node_modules/node-pty> [--out <dir>]
//   (or set PGARD_NODE_PTY=<dir>; the directory is where `npm install node-pty` was run)
//
// node-pty is never a dependency of this repository: it is installed somewhere else and found
// through that path.
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { cliText } from "../../apps/cli/dist/ui/i18n/cli-text.js";
import { displayWidth } from "../../apps/cli/dist/ui/i18n/display-width.js";
import { Screen } from "./screen.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../..");
const entry = join(here, "run-panels.mjs");

function option(name, envName) {
  const index = process.argv.indexOf(name);
  if (index > 0 && process.argv[index + 1]) return process.argv[index + 1];
  return process.env[envName];
}

const ptyDir = option("--node-pty", "PGARD_NODE_PTY");
if (!ptyDir) {
  console.error(
    "Pass --node-pty <dir> or set PGARD_NODE_PTY (the dir where node-pty was installed).",
  );
  process.exit(2);
}
const pty = createRequire(join(resolve(ptyDir), "noop.js"))("node-pty");
const outDir = resolve(
  option("--out", "PGARD_SMOKE_OUT") ?? mkdtempSync(join(tmpdir(), "pgard-pty-")),
);
mkdirSync(outDir, { recursive: true });

const t = cliText("ko").panels;
const ENTER = "\u001b[?1049h";
const LEAVE = "\u001b[?1049l";
const KEYS = {
  tab: "\t",
  down: "\u001b[B",
  pageDown: "\u001b[6~",
  help: "?",
  esc: "\u001b",
  ctrlC: "\u0003",
};

const sleep = (ms) => new Promise((done) => setTimeout(done, ms));
const results = [];
const transcripts = [];

function check(scenario, name, ok, detail = "") {
  results.push({ scenario, name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"}  [${scenario}] ${name}${detail ? ` - ${detail}` : ""}`);
}

/** Starts the panel run in a pty and returns helpers to type, resize and wait. */
function start(label, columns, rows) {
  const env = { ...process.env };
  for (const name of ["NO_COLOR", "COLUMNS", "LINES", "PGARD_PANELS_ONCE", "PGARD_PANELS"]) {
    delete env[name];
  }
  Object.assign(env, {
    PGARD_LANG: "ko",
    TERM: "xterm-256color",
    // Nothing is written there (the run has no result store); set anyway so a real path is never used.
    XDG_DATA_HOME: mkdtempSync(join(tmpdir(), "pgard-xdg-")),
  });
  const term = pty.spawn(process.execPath, [entry], {
    name: "xterm-256color",
    cols: columns,
    rows,
    cwd: repoRoot,
    env,
  });
  const run = {
    label,
    term,
    raw: "",
    chunks: [],
    screen: new Screen(columns, rows),
    lastData: Date.now(),
    exit: null,
    started: Date.now(),
  };
  term.onData((data) => {
    run.screen.feed(data, run.raw.length);
    run.raw += data;
    run.chunks.push({ at: Date.now() - run.started, data });
    run.lastData = Date.now();
  });
  term.onExit((event) => {
    run.exit = { exitCode: event.exitCode, signal: event.signal ?? null };
  });
  return run;
}

async function waitFor(run, predicate, what, timeout = 20000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (predicate()) return true;
    await sleep(50);
  }
  console.log(`  timeout waiting for ${what}`);
  return false;
}

/** Waits until the output has been quiet for `quiet` ms (the redraw is finished). */
async function settle(run, quiet = 300, timeout = 4000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (Date.now() - run.lastData >= quiet) return;
    await sleep(50);
  }
}

async function press(run, name) {
  const before = run.raw.length;
  run.term.write(KEYS[name]);
  await waitFor(run, () => run.raw.length > before, `output after ${name}`, 3000);
  await settle(run);
  return run.raw.length > before;
}

async function waitForExit(run) {
  const done = await waitFor(run, () => run.exit !== null, "process exit", 20000);
  await sleep(300);
  return done;
}

function modeOrder(run, mode) {
  return run.screen.modes.filter((event) => event.mode === mode);
}

function terminalRestored(scenario, run) {
  const alt = modeOrder(run, 1049);
  const enters = alt.filter((event) => event.on).length;
  const leaves = alt.filter((event) => !event.on).length;
  check(
    scenario,
    "alternate screen entered and left, paired",
    enters >= 1 && enters === leaves,
    `enter=${enters} leave=${leaves}`,
  );
  check(
    scenario,
    "last alternate-screen switch is the leave",
    alt.length > 0 && !alt[alt.length - 1].on,
  );
  const cursor = modeOrder(run, 25);
  const lastHide = cursor.map((event) => event.on).lastIndexOf(false);
  const lastShow = cursor.map((event) => event.on).lastIndexOf(true);
  check(scenario, "cursor shown again after the last hide", lastHide >= 0 && lastShow > lastHide);
}

// The only escape sequences the panel view writes itself are CSI ones (cursor, erase, colour,
// screen switch). The pty layer may add a window title (OSC 0/2); that is removed only when it
// carries none of the fixture's text. Whatever is left must be plain text.
const CSI = /\u001b\[[0-9;?]*[ -/]*[@-~]/gu;
const OSC_TITLE = /\u001b\][02];([^\u0007\u001b]*)(?:\u0007|\u001b\\)/gu;

function noRawControls(scenario, run) {
  let text = run.raw.replace(OSC_TITLE, (match, title) => (/PWNED|evil/u.test(title) ? match : ""));
  text = text.replace(CSI, "");
  const found = [];
  if (/\u001b/u.test(text)) found.push("ESC");
  if (/\u0007/u.test(text)) found.push("BEL");
  if (/[\u0080-\u009f]/u.test(text)) found.push("C1");
  if (/‮/u.test(text)) found.push("U+202E");
  if (/[\u0000-\u0006\u0008\u000b\u000c\u000e-\u001a\u001c-\u001f\u007f]/u.test(text))
    found.push("other C0");
  check(
    scenario,
    "no raw ESC/OSC/BEL/C1/U+202E from the fixture reach the terminal",
    found.length === 0,
    found.join(", "),
  );
}

async function firstFrame(scenario, run) {
  const ok = await waitFor(
    run,
    () => Object.values(t.tabs).every((label) => run.screen.text().includes(label)),
    "first frame",
  );
  check(scenario, "first frame drawn", ok);
  await settle(run);
  return ok;
}

function koreanChrome(scenario, run) {
  const screen = run.screen.text();
  const tabs = Object.values(t.tabs);
  const present = tabs.filter((label) => screen.includes(label));
  check(
    scenario,
    "Korean chrome present (tab labels)",
    present.length === tabs.length,
    `${present.length}/${tabs.length} on screen`,
  );
}

function transcript(run) {
  transcripts.push(
    `===== ${run.label} (exit ${JSON.stringify(run.exit)}) =====\n` +
      run.chunks
        .map((chunk) => `${String(chunk.at).padStart(6)}ms ${JSON.stringify(chunk.data)}`)
        .join("\n") +
      "\n",
  );
}

// ---- run 1: keys, resize, Ctrl+C, y -> 130 -------------------------------------------------
async function runCancel() {
  const scenario = "cancel";
  const run = start(scenario, 80, 24);
  try {
    if (!(await firstFrame(scenario, run))) return run;
    koreanChrome(scenario, run);
    const redrew = {};
    for (const name of ["tab", "down", "pageDown", "help", "esc"])
      redrew[name] = await press(run, name);
    check(
      scenario,
      "every scripted key (Tab, Down, PageDown, ?, Esc) redrew the screen",
      Object.values(redrew).every(Boolean),
      JSON.stringify(redrew),
    );

    const mark = run.raw.length;
    run.screen.resize(60, 20);
    run.term.resize(60, 20);
    await waitFor(run, () => run.raw.length > mark, "redraw after resize", 5000);
    await settle(run, 500);
    check(
      scenario,
      "redraw after the resize",
      run.raw.length > mark,
      `${run.raw.length - mark} bytes`,
    );
    const lines = run.screen.lines();
    const widest = Math.max(...lines.map((line) => displayWidth(line)));
    check(
      scenario,
      "after the resize no line is wider than 60 columns",
      run.screen.overflow === 0 && widest <= 60,
      `overflow=${run.screen.overflow} widest=${widest}`,
    );
    check(
      scenario,
      "the redrawn screen still has the Korean tab labels",
      Object.values(t.tabs).every((label) => run.screen.text().includes(label)),
    );

    run.term.write(KEYS.ctrlC);
    const asked = await waitFor(
      run,
      () => run.screen.text().includes(t.confirmCancel),
      "cancel question",
      5000,
    );
    check(scenario, "Ctrl+C asks to confirm in Korean", asked);
    await settle(run);
    run.term.write("y");
    await waitForExit(run);
    check(scenario, "exit code 130", run.exit?.exitCode === 130, JSON.stringify(run.exit));
    terminalRestored(scenario, run);
    noRawControls(scenario, run);
  } finally {
    run.term.kill?.();
  }
  return run;
}

// ---- run 2: q -> 0 -------------------------------------------------------------------------
async function runQuit() {
  const scenario = "quit";
  const run = start(scenario, 80, 24);
  try {
    if (!(await firstFrame(scenario, run))) return run;
    run.term.write("q");
    await waitForExit(run);
    check(scenario, "exit code 0", run.exit?.exitCode === 0, JSON.stringify(run.exit));
    terminalRestored(scenario, run);
    const beforeEnter = run.raw.slice(0, Math.max(0, run.raw.indexOf(ENTER)));
    check(
      scenario,
      "the text result stayed on the main screen (printed before the panel view)",
      beforeEnter.includes("PGARD"),
    );
    noRawControls(scenario, run);
  } finally {
    run.term.kill?.();
  }
  return run;
}

// ---- run 3: SIGTERM -> 143 (not where the platform has no signals) ---------------------------
async function runTerminate() {
  const scenario = "sigterm";
  if (process.platform === "win32") {
    // node-pty's Windows terminal throws "Signals not supported on windows." for any named
    // signal, and kill() without one ends the process hard (TerminateProcess), so the SIGTERM
    // handler cannot run. Exit code 143 is therefore not reachable from a ConPTY; it is covered
    // by the controller unit tests and by this run on macOS and Linux.
    console.log(
      `SKIP  [${scenario}] SIGTERM cannot be delivered through ConPTY (node-pty has no signals on Windows)`,
    );
    results.push({
      scenario,
      name: "SIGTERM exit 143",
      ok: true,
      skipped: true,
      detail: "not supported on Windows",
    });
    return null;
  }
  const run = start(scenario, 80, 24);
  try {
    if (!(await firstFrame(scenario, run))) return run;
    run.term.kill("SIGTERM");
    await waitForExit(run);
    check(scenario, "exit code 143", run.exit?.exitCode === 143, JSON.stringify(run.exit));
    terminalRestored(scenario, run);
    noRawControls(scenario, run);
  } finally {
    run.term.kill?.();
  }
  return run;
}

console.log(`node ${process.version} on ${process.platform}/${process.arch}; output in ${outDir}`);
for (const scenarioRun of [runCancel, runQuit, runTerminate]) {
  try {
    const run = await scenarioRun();
    if (run) transcript(run);
  } catch (error) {
    check(
      scenarioRun.name,
      "scenario ran without an exception",
      false,
      String(error?.stack ?? error),
    );
  }
}
writeFileSync(join(outDir, "transcript.txt"), transcripts.join("\n"));
writeFileSync(
  join(outDir, "results.json"),
  `${JSON.stringify({ node: process.version, platform: process.platform, results }, null, 2)}\n`,
);
const failed = results.filter((result) => !result.ok);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
