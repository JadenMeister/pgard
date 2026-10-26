import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createInMemoryCredentialStore, type SignInNotice } from "@pgard/scan-core";
import { describe, expect, it } from "vitest";
import { main } from "./app.js";
import { runDoctor } from "./commands/doctor.js";
import { runLogout } from "./commands/login.js";
import { runRulesList } from "./commands/rules/list.js";
import {
  formatDeviceCode,
  formatGitHubAppOverride,
  formatSignInNotice,
} from "./flows/authenticate.js";
import { checkOutputDir, confirmInsideRepository, saveReports } from "./flows/export-report.js";
import {
  formatAskOwner,
  formatAskOwnerToAddRepository,
  formatOwnerOrAsk,
  waitingMessage,
} from "./flows/guided-install.js";
import { createTestContext, createTestDeps, createTestIo, testResult } from "./test-support.js";
import { CLI_TEXT } from "./ui/i18n/cli-text.js";

const HANGUL = /[가-힣]/;
const KO = CLI_TEXT.ko;

function koContext(captured: ReturnType<typeof createTestIo>, deps = createTestDeps()) {
  return { ...createTestContext(captured, deps), ruleLocale: "ko" as const };
}

describe("sign-in text in Korean", () => {
  it("shows the device code instructions with the code and link intact", () => {
    const text = formatDeviceCode(
      { verificationUri: "https://github.com/login/device", userCode: "WXYZ-1234", expiresIn: 900 },
      KO,
    );
    expect(text).toMatch(HANGUL);
    expect(text).toContain("https://github.com/login/device");
    expect(text).toContain("WXYZ-1234");
    expect(text).toContain("15분");
    expect(text).not.toContain("Waiting for approval");
  });

  it("translates every kind of sign-in notice and the override line", () => {
    const notices: SignInNotice[] = [
      { kind: "reused", login: "octo", userId: 7, isRefreshed: true },
      { kind: "saved", login: "octo", userId: 7 },
      { kind: "removed", reason: "expired" },
      { kind: "removed", reason: "revoked" },
      { kind: "removed", reason: "refresh_failed" },
      { kind: "removed", reason: "malformed" },
      { kind: "memory_only", reason: "no keychain" },
    ];
    for (const notice of notices) {
      const text = formatSignInNotice(notice, KO);
      expect(text, notice.kind).toMatch(HANGUL);
      expect(text).not.toBe(formatSignInNotice(notice));
    }
    expect(formatSignInNotice(notices[0] as SignInNotice, KO)).toContain("octo");
    expect(formatGitHubAppOverride("Iv23liX", KO)).toContain("PGARD_GITHUB_APP_CLIENT_ID");
    expect(formatGitHubAppOverride("Iv23liX", KO)).toMatch(HANGUL);
  });

  it("logout says so in Korean when nothing is saved, and when the keychain is gone", async () => {
    const captured = createTestIo();
    const code = await runLogout(
      koContext(captured, createTestDeps({ credentialStore: createInMemoryCredentialStore() })),
    );
    expect(code).toBe(0);
    expect(captured.stdout()).toContain("저장된 GitHub 로그인이 없습니다");
    expect(captured.stdout()).not.toContain("No GitHub sign-in");
  });
});

describe("App install text in Korean", () => {
  it("keeps names and links while translating the sentence", () => {
    const url = "https://github.com/apps/pgard/installations/new";
    for (const text of [
      formatAskOwner("octo-org", url, KO),
      formatOwnerOrAsk("octo-org", url, KO),
      formatAskOwnerToAddRepository("octo-org", "octo-org/app", url, KO),
      formatAskOwnerToAddRepository("octo-org", null, url, KO),
    ]) {
      expect(text).toMatch(HANGUL);
      expect(text).toContain("octo-org");
      expect(text).toContain(url);
    }
    expect(formatAskOwnerToAddRepository("o", "o/app", "u", KO)).toContain("o/app");
    expect(formatAskOwnerToAddRepository("o", null, "u", KO)).toContain("이 저장소");
    expect(waitingMessage("installation", null, KO)).toMatch(HANGUL);
    expect(waitingMessage("repository_access", "o/app", KO)).toContain("o/app");
  });
});

describe("report export text in Korean", () => {
  it("translates the output directory errors for the option and for the prompt", async () => {
    const captured = createTestIo();
    const context = koContext(captured);
    const root = mkdtempSync(join(tmpdir(), "pgard-ko-"));
    try {
      const missing = await checkOutputDir(context, join(root, "nope"), root);
      expect(missing).toEqual({
        kind: "invalid",
        message: expect.stringContaining("--output-dir"),
      });
      expect(missing.kind === "invalid" && missing.message).toMatch(HANGUL);
      const typed = await checkOutputDir(context, join(root, "nope"), root, "prompt");
      expect(typed.kind === "invalid" && typed.message).toBe("그 경로가 없습니다. 먼저 만드세요.");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("warns in Korean about a directory inside the repository, and cannot confirm without a TTY", async () => {
    const captured = createTestIo();
    expect(await confirmInsideRepository(koContext(captured))).toBe(false);
    expect(captured.stderr()).toContain("경고: 출력 디렉터리가 Git 저장소 안에 있습니다");
    expect(captured.stderr()).toContain("대화형 터미널이 아니면 확인할 수 없습니다");
  });

  it("reports saved files and failures in Korean", async () => {
    const saved = createTestIo();
    const okDeps = createTestDeps({
      writeReports: (async () => [{ format: "html", filePath: "/out/r.html" }]) as never,
    });
    expect(await saveReports(koContext(saved, okDeps), testResult(), "html", "/out")).toBe(true);
    expect(saved.stdout()).toContain("HTML 보고서를 저장했습니다: /out/r.html");
    const failed = createTestIo();
    const badDeps = createTestDeps({
      writeReports: (async () => {
        throw new Error("boom");
      }) as never,
    });
    expect(await saveReports(koContext(failed, badDeps), testResult(), "html", "/out")).toBe(false);
    expect(failed.stderr()).toContain("보고서를 쓰는 중 예기치 않은 오류가 발생했습니다.");
  });
});

describe("pgard doctor in Korean", () => {
  it("translates the title, labels, details and the summary line", async () => {
    const captured = createTestIo();
    expect(await runDoctor(koContext(captured))).toBe(0);
    const stdout = captured.stdout();
    for (const expected of [
      "pgard doctor (진단만 수행하며 권한 확인이 아닙니다)",
      "GitHub 연결: api.github.com에 연결됨",
      "GitHub App: 내장 PGARD App (",
      "저장된 GitHub 로그인:",
      "취약점 데이터 (OSV):",
      "로컬 포트 탐색:",
      "[ok]",
    ]) {
      expect(stdout, expected).toContain(expected);
    }
    expect(stdout).not.toContain("diagnosis only");
    expect(stdout).not.toContain("required checks");
  });

  it("reads the language from the environment, and a bad PGARD_LANG does not break it", async () => {
    const ko = createTestIo({ env: { PGARD_LANG: "ko" } });
    expect(await main(["doctor"], ko.io, { deps: createTestDeps() })).toBe(0);
    expect(ko.stdout()).toContain("진단만 수행하며");
    const bad = createTestIo({ env: { PGARD_LANG: "fr" } });
    expect(await main(["doctor"], bad.io, { deps: createTestDeps() })).toBe(0);
    expect(bad.stdout()).toContain("diagnosis only");
    const plain = createTestIo({ env: { LC_ALL: "C" } });
    expect(await main(["doctor"], plain.io, { deps: createTestDeps() })).toBe(0);
    expect(plain.stdout()).toContain("diagnosis only");
  });
});

describe("pgard rules list in Korean", () => {
  it("translates headings, the filter line and the unsupported areas, not rule ids", async () => {
    const captured = createTestIo();
    expect(await runRulesList(koContext(captured), "react")).toBe(0);
    const stdout = captured.stdout();
    for (const expected of [
      "탐지 기준",
      "언어 필터: react (javascript/typescript 규칙과 모든 언어용 규칙을 포함)",
      "코드 규칙 (현재 파일)",
      "Git 이력 규칙",
      "로컬 HTTP 규칙 (익명 GET, 모든 언어)",
      "이 버전에서 다루지 않는 영역",
      "  - 데이터베이스 직접 연결",
      "PG-SQL-001",
    ]) {
      expect(stdout, expected).toContain(expected);
    }
    expect(stdout).not.toContain("Language filter");
    expect(stdout).not.toContain("Not covered in this version");
  });

  it("lists as many unsupported areas in Korean as in English", () => {
    expect(KO.commands.rulesList.unsupportedAreas).toHaveLength(
      CLI_TEXT.en.commands.rulesList.unsupportedAreas.length,
    );
  });
});
