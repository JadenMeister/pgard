import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { createResultStore, type ResultStore } from "@pgard/result-store";
import type { AuthorizationOutcome } from "@pgard/scan-core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  ALLOWED,
  createTestContext,
  createTestDeps,
  createTestIo,
  testFinding,
  testResult,
} from "../../test-support.js";
import { formatProgress } from "./index.js";
import { runScanCommand, type ScanCommand } from "./index.js";
import { cliText } from "../../ui/i18n/cli-text.js";

const OUTCOME: AuthorizationOutcome = {
  summary: ALLOWED,
  repo: "owner/name",
  revision: "abc",
  repositoryId: 4242,
};
const SCAN: ScanCommand = { variant: "code", requireAuthorization: true, port: null, report: null };

let base: string;
let store: ResultStore;
beforeEach(async () => {
  base = await mkdtemp(path.join(os.tmpdir(), "pgard-cli-locale-"));
  store = createResultStore({ dir: path.join(base, "pgard") });
});
afterEach(async () => {
  await rm(base, { recursive: true, force: true });
});

function deps(result = testResult(), withStore = false) {
  return createTestDeps({
    openResultStore: () => (withStore ? store : null),
    runScan: async (_request, scanDeps) => {
      scanDeps?.onAuthorization?.(OUTCOME);
      scanDeps?.onProgress?.({
        stage: "code",
        status: "started",
        message: "Running code analysis.",
      });
      scanDeps?.onProgress?.({
        stage: "web",
        status: "skipped",
        message: "No confirmed local web target.",
      });
      return result;
    },
  });
}

async function run(locale: "en" | "ko", command: ScanCommand = SCAN, scanDeps = deps()) {
  const captured = createTestIo();
  const context = { ...createTestContext(captured, scanDeps), ruleLocale: locale };
  const code = await runScanCommand(context, command);
  return { code, stdout: captured.stdout(), stderr: captured.stderr() };
}

describe("terminal language of the scan screens", () => {
  it("keeps English by default", async () => {
    const { stdout, stderr } = await run("en");
    expect(stdout).toContain("PGARD scan result - Completed");
    expect(stderr).toContain("Scanning (code)... Press Ctrl+C twice to cancel.");
    expect(stderr).toContain("  code: started - Running code analysis.");
  });

  it("shows the result screen, the status line and the progress in Korean", async () => {
    const { stdout, stderr } = await run("ko");
    expect(stdout).toContain("PGARD 검사 결과 - 완료");
    expect(stdout).toContain("검사 범위");
    expect(stdout).not.toContain("PGARD scan result");
    expect(stderr).toContain("검사 중 (code)... 취소하려면 Ctrl+C를 두 번 누르세요.");
    expect(stderr).toContain("  코드: 시작");
    expect(stderr).toContain("  웹: 건너뜀 - 확인된 로컬 웹 대상이 없습니다.");
  });

  it("never translates --format json", async () => {
    const json: ScanCommand = { ...SCAN, format: "json" };
    const english = await run("en", json);
    const korean = await run("ko", json);
    expect(korean.stdout).toBe(english.stdout);
    expect(JSON.parse(korean.stdout)).toMatchObject({ overallStatus: "completed" });
    expect(korean.stdout).not.toMatch(/[ㄱ-힝]/);
  });

  it("shows what changed since the last scan in the summary, in the terminal language", async () => {
    const first = testResult({ scanId: "scan-1", findings: [testFinding({ id: "a" })] });
    const second = testResult({
      scanId: "scan-2",
      findings: [testFinding({ id: "a" }), testFinding({ id: "b", ruleId: "PG-XSS-001" })],
    });
    await run("en", SCAN, deps(first, true));
    const english = await run("en", SCAN, deps(second, true));
    expect(english.stdout).toMatch(/Since last scan +\+\d+ new \/ -\d+ no longer reported/);
    expect(english.stdout).toContain("Since the last scan (");

    const third = testResult({ scanId: "scan-3", findings: [testFinding({ id: "a" })] });
    const korean = await run("ko", SCAN, deps(third, true));
    expect(korean.stdout).toMatch(/지난 검사 대비 +신규 \d+건 \/ 더 이상 보고되지 않음 \d+건/);
    expect(korean.stdout).toContain("지난 검사 이후 (");
    expect(korean.stdout).not.toContain("Since the last scan");
  });

  it("translates the first-run storage notice", async () => {
    const { stderr } = await run("ko", SCAN, deps(testResult(), true));
    expect(stderr).toContain("PGARD가 이제 이 컴퓨터에 검사 결과를 보관해");
    expect(stderr).toContain("--no-store");
  });
});

describe("progress lines", () => {
  it("leave unknown stages and messages as written in Korean", () => {
    const ko = cliText("ko");
    expect(
      formatProgress(
        { stage: "future", status: "started", message: "Something new." } as never,
        ko,
      ),
    ).toBe("  future: 시작");
    expect(
      formatProgress(
        { stage: "web", status: "started", message: "", web: { pagesVisited: 3 } } as never,
        ko,
      ),
    ).toBe("  웹: 페이지 3개 확인함");
  });
});

describe("Korean progress messages", () => {
  const ko = cliText("ko");
  const messages = [
    ["authorization", "started", "Verifying repository authorization."],
    ["authorization", "failed", "Authorization check failed."],
    ["authorization", "failed", "Scan blocked by authorization gate."],
    ["authorization", "completed", "Authorization verified."],
    ["web", "skipped", "No confirmed local web target."],
    ["web", "skipped", "Web scanner unavailable."],
    ["web", "started", "Checking local web pages."],
    ["code", "started", "Running code analysis."],
    ["history", "completed", "Finished history analysis."],
    ["web", "failed", "The web analysis failed."],
  ] as const;

  it("translates every fixed message of the scan", () => {
    for (const [stage, status, message] of messages) {
      const line = formatProgress({ stage, status, message } as never, ko) ?? "";
      expect(line, message).not.toMatch(/[A-Za-z]{4,} [a-z]+/);
      expect(line, message).toContain(" - ");
    }
  });

  it("says a blocked scan was blocked, not that it failed generically", () => {
    const blocked = formatProgress(
      {
        stage: "authorization",
        status: "failed",
        message: "Scan blocked by authorization gate.",
      } as never,
      ko,
    );
    expect(blocked).toContain("권한 확인에서 검사가 차단되었습니다");
    const failed = formatProgress(
      { stage: "authorization", status: "failed", message: "Authorization check failed." } as never,
      ko,
    );
    expect(failed).toContain("권한 확인에 실패했습니다");
  });
});
