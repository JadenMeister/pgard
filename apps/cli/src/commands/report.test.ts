import { mkdir, mkdtemp, readFile, readdir, rm, stat } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import type { ScanResult } from "@pgard/findings";
import { writeReports } from "@pgard/report";
import { createResultStore, type ResultStore } from "@pgard/result-store";
import type { AuthorizationOutcome } from "@pgard/scan-core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { main } from "../app.js";
import type { CliDeps } from "../deps.js";
import {
  ALLOWED,
  BLOCKED,
  createSignedInCredentialStore,
  createTestContext,
  createTestDeps,
  createTestIo,
  noInterrupts,
  testResult,
} from "../test-support.js";
import { CLI_TEXT } from "../ui/i18n/cli-text.js";
import { runReport, type ReportCommand } from "./report.js";

const REPO_ID = 4242;
const SCAN_REVISION = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HEAD_REVISION = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const OUTCOME: AuthorizationOutcome = {
  summary: ALLOWED,
  repo: "owner/name",
  revision: SCAN_REVISION,
  repositoryId: REPO_ID,
};
const HTML: ReportCommand = { format: "html", outputDir: null, noOpen: false };

let base: string;
let reportDir: string;
let store: ResultStore;
let opened: string[];
let readIds: number[];

beforeEach(async () => {
  base = await mkdtemp(path.join(os.tmpdir(), "pgard-cli-report-"));
  reportDir = path.join(base, "reports");
  await mkdir(reportDir);
  store = createResultStore({ dir: path.join(base, "pgard") });
  opened = [];
  readIds = [];
});
afterEach(async () => {
  await rm(base, { recursive: true, force: true });
});

async function save(
  repositoryId: number,
  overrides: Partial<ScanResult> = {},
): Promise<ScanResult> {
  const result = testResult({
    target: { repo: "owner/name", revision: SCAN_REVISION, webOrigin: null },
    ...overrides,
  });
  const saved = await store.save(result, { repositoryId, forbidSubstrings: [] });
  expect(saved.ok).toBe(true);
  return result;
}

/** The test store, recording which repository ids were read. */
function recordingStore(): ResultStore {
  return {
    ...store,
    dir: store.dir,
    findNewest: (id, accept) => {
      readIds.push(id);
      return store.findNewest(id, accept);
    },
    list: (id, options) => {
      readIds.push(id);
      return store.list(id, options);
    },
  };
}

function deps(
  options: { outcome?: AuthorizationOutcome; resultStore?: ResultStore | null } = {},
): CliDeps {
  const outcome = options.outcome ?? OUTCOME;
  const resultStore = options.resultStore === undefined ? recordingStore() : options.resultStore;
  return createTestDeps({
    openResultStore: () => resultStore,
    verifyProject: async () => outcome,
    writeReports,
    reportDefaultDir: () => reportDir,
    openLocalFile: async (file) => {
      opened.push(file);
      return true;
    },
  });
}

async function report(
  command: ReportCommand = HTML,
  options: {
    deps?: CliDeps;
    isTTY?: boolean;
    env?: Record<string, string>;
    locale?: "en" | "ko";
  } = {},
) {
  const captured = createTestIo({ isTTY: options.isTTY ?? true, env: options.env ?? {} });
  const context = {
    ...createTestContext(captured, options.deps ?? deps()),
    ruleLocale: options.locale ?? ("en" as const),
  };
  const code = await runReport(context, command);
  return { captured, code };
}

describe("runReport", () => {
  it("tells the user to run pgard scan first when nothing is stored (exit 2)", async () => {
    const { captured, code } = await report();
    expect(code).toBe(2);
    expect(captured.stderr()).toContain("pgard scan");
    expect(captured.stderr()).toContain("owner/name");
    expect(await readdir(reportDir)).toEqual([]);
    expect(opened).toEqual([]);
  });

  it("says the same in Korean", async () => {
    const { captured, code } = await report(HTML, { locale: "ko" });
    expect(code).toBe(2);
    expect(captured.stderr()).toContain("pgard scan");
    expect(captured.stderr()).toMatch(/[가-힣]/);
  });

  it("refuses a result stored for another repository and reads only its own id", async () => {
    await save(REPO_ID + 1, { scanId: "other-repo-scan" });
    const { captured, code } = await report();
    expect(code).toBe(2);
    expect(readIds).toEqual([REPO_ID]);
    expect(captured.stdout()).not.toContain("other-repo-scan");
    expect(await readdir(reportDir)).toEqual([]);
    expect(opened).toEqual([]);
  });

  it("reads nothing when the repository cannot be verified (exit 3)", async () => {
    await save(REPO_ID);
    const { captured, code } = await report(HTML, {
      deps: deps({ outcome: { summary: BLOCKED, repo: "owner/name", revision: "abc" } }),
    });
    expect(code).toBe(3);
    expect(readIds).toEqual([]);
    expect(captured.stderr()).toContain("could not be verified");
    expect(await readdir(reportDir)).toEqual([]);
  });

  it("reads nothing when the gate allowed but gave no repository id", async () => {
    await save(REPO_ID);
    const { code } = await report(HTML, {
      deps: deps({ outcome: { summary: ALLOWED, repo: "owner/name", revision: "abc" } }),
    });
    expect(code).toBe(3);
    expect(readIds).toEqual([]);
  });

  it("refuses to run with PGARD_NO_STORE=1", async () => {
    await save(REPO_ID);
    const { captured, code } = await report(HTML, { env: { PGARD_NO_STORE: "1" } });
    expect(code).toBe(2);
    expect(readIds).toEqual([]);
    expect(captured.stderr()).toContain("PGARD_NO_STORE=1");
  });

  it("writes an HTML report with a fixed name and mode 0600, then opens it", async () => {
    await save(REPO_ID, { scanId: "scan-current-1" });
    const { captured, code } = await report();
    expect(code).toBe(0);
    const files = await readdir(reportDir);
    expect(files).toHaveLength(1);
    const file = path.join(reportDir, files[0] ?? "");
    expect(files[0]).toMatch(/^pgard-report-\d{14}-[A-Za-z0-9]{1,8}\.html$/);
    if (process.platform !== "win32") expect((await stat(file)).mode & 0o777).toBe(0o600);
    const html = await readFile(file, "utf8");
    expect(html).toContain("scan-current-1");
    expect(html).toContain(SCAN_REVISION);
    expect(html).toContain("2026-10-24T00:00:00.000Z");
    expect(captured.stdout()).toContain("Saved HTML report:");
    expect(opened).toHaveLength(1);
    expect(opened[0]).toContain(".html");
    expect(captured.stdout()).not.toContain("Note: this report is from");
  });

  it("writes a PDF with --format pdf", async () => {
    await save(REPO_ID);
    const { code } = await report({ ...HTML, format: "pdf" });
    expect(code).toBe(0);
    const files = await readdir(reportDir);
    expect(files).toHaveLength(1);
    expect(files[0]).toMatch(/\.pdf$/);
    const bytes = await readFile(path.join(reportDir, files[0] ?? ""));
    expect(bytes.subarray(0, 5).toString("latin1")).toBe("%PDF-");
    expect(opened[0]).toMatch(/\.pdf$/);
  });

  it("writes to --output-dir", async () => {
    await save(REPO_ID);
    const other = path.join(base, "elsewhere");
    await mkdir(other);
    const { code } = await report({ ...HTML, outputDir: other });
    expect(code).toBe(0);
    expect(await readdir(other)).toHaveLength(1);
    expect(await readdir(reportDir)).toEqual([]);
  });

  it("rejects a missing --output-dir before any check (exit 2)", async () => {
    await save(REPO_ID);
    const { code } = await report({ ...HTML, outputDir: path.join(base, "nope") });
    expect(code).toBe(2);
    expect(readIds).toEqual([]);
  });

  it("with --no-open writes the file, prints its path and opens nothing", async () => {
    await save(REPO_ID);
    const { captured, code } = await report({ ...HTML, noOpen: true });
    expect(code).toBe(0);
    expect(opened).toEqual([]);
    const files = await readdir(reportDir);
    expect(captured.stdout()).toContain(files[0]);
  });

  it("never opens without a terminal, but still prints the path", async () => {
    await save(REPO_ID);
    const { captured, code } = await report(HTML, { isTTY: false });
    expect(code).toBe(0);
    expect(opened).toEqual([]);
    expect(captured.stdout()).toContain("Saved HTML report:");
  });

  it("never opens in CI even in a terminal", async () => {
    await save(REPO_ID);
    const { code } = await report(HTML, { env: { CI: "true" } });
    expect(code).toBe(0);
    expect(opened).toEqual([]);
  });

  it("shows the scan time and commit in a one-line note when HEAD has moved", async () => {
    await save(REPO_ID);
    const { captured, code } = await report(HTML, {
      deps: deps({ outcome: { ...OUTCOME, revision: HEAD_REVISION } }),
    });
    expect(code).toBe(0);
    const note = captured
      .stdout()
      .split("\n")
      .filter((line) => line.startsWith("Note: this report is from"));
    expect(note).toHaveLength(1);
    expect(note[0]).toContain(SCAN_REVISION.slice(0, 12));
    expect(note[0]).toContain(HEAD_REVISION.slice(0, 12));
    expect(note[0]).toMatch(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}/);
    const files = await readdir(reportDir);
    expect(await readFile(path.join(reportDir, files[0] ?? ""), "utf8")).toContain(SCAN_REVISION);
  });

  it("prints the stale note in Korean", async () => {
    await save(REPO_ID);
    const { captured } = await report(HTML, {
      locale: "ko",
      deps: deps({ outcome: { ...OUTCOME, revision: HEAD_REVISION } }),
    });
    expect(captured.stdout()).toContain("참고:");
    expect(captured.stdout()).toContain(SCAN_REVISION.slice(0, 12));
  });

  it("never overwrites: a second run for the same scan exits 4 and keeps the file", async () => {
    await save(REPO_ID);
    expect((await report({ ...HTML, noOpen: true })).code).toBe(0);
    const [name] = await readdir(reportDir);
    const before = await readFile(path.join(reportDir, name ?? ""), "utf8");
    const second = await report({ ...HTML, noOpen: true });
    expect(second.code).toBe(4);
    expect(second.captured.stderr()).toContain("never overwritten");
    expect(await readFile(path.join(reportDir, name ?? ""), "utf8")).toBe(before);
  });

  it("says when the report was written but could not be opened", async () => {
    await save(REPO_ID);
    const failing = { ...deps(), openLocalFile: async () => false };
    const { captured, code } = await report(HTML, { deps: failing });
    expect(code).toBe(0);
    expect(captured.stderr()).toContain("could not be opened automatically");
  });

  it("has Korean text for every message", () => {
    const en = CLI_TEXT.en.commands.reportCommand;
    const ko = CLI_TEXT.ko.commands.reportCommand;
    expect(Object.keys(ko).sort()).toEqual(Object.keys(en).sort());
    expect(ko.menuLabel).not.toBe(en.menuLabel);
  });
});

describe("menu entry", () => {
  async function runMenu(env: Record<string, string>, keysAfterMenu: string[]) {
    const captured = createTestIo({ isTTY: true, env });
    const { stdin } = captured;
    stdin.setRawMode = () => undefined;
    const running = main([], captured.io, {
      deps: {
        ...deps(),
        createSessionProvider: () => (async () => ({})) as never,
        credentialStore: createSignedInCredentialStore(),
      },
      interrupts: noInterrupts,
    });
    const press = async (sequence: string, wait = 20): Promise<void> => {
      await new Promise((resolve) => setTimeout(resolve, wait));
      stdin.write(sequence);
    };
    // verify, scan, scan code, scan history, scan web, scan all, then the report entry.
    for (let index = 0; index < 6; index += 1) await press("\u001b[B");
    for (const key of keysAfterMenu) await press(key, key === "\u001b" ? 700 : 300);
    return { captured, code: await running };
  }

  it("lists the entry in English and builds an HTML report from the stored scan", async () => {
    await save(REPO_ID);
    const { captured, code } = await runMenu({}, ["\r", "\r", "x", "\u001b"]);
    expect(code).toBe(0);
    expect(captured.stdout()).toContain("Build report from last scan");
    expect(captured.stdout()).toContain("Saved HTML report:");
    expect(opened).toHaveLength(1);
    expect(await readdir(reportDir)).toHaveLength(1);
  }, 10_000);

  it("lists the entry in Korean", async () => {
    const { captured, code } = await runMenu({ PGARD_LANG: "ko" }, ["\u001b"]);
    expect(code).toBe(0);
    expect(captured.stdout()).toContain("마지막 검사로 보고서 만들기");
  }, 10_000);
});
