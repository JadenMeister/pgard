import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { createInMemoryCredentialStore } from "@pgard/scan-core";
import { afterEach, describe, expect, it } from "vitest";
import { createTestContext, createTestDeps, createTestIo } from "../test-support.js";
import { isSupportedNodeVersion, runDoctor } from "./doctor.js";

const scratch: string[] = [];
afterEach(async () => {
  for (const dir of scratch.splice(0)) await rm(dir, { recursive: true, force: true });
});

/** A one-ecosystem OSV store in a scratch folder (never the real per-user folder). */
async function fixtureStore(fetchedAt: string, modifiedMax: string): Promise<string> {
  const appData = await mkdtemp(path.join(tmpdir(), "pgard-doctor-"));
  scratch.push(appData);
  const bytes = Buffer.from("fixture");
  for (const ecosystem of ["npm", "Go"]) {
    const dir = path.join(appData, "advisories", "osv", ecosystem);
    await mkdir(dir, { recursive: true });
    await writeFile(path.join(dir, "advisories.jsonl.gz"), bytes);
    const meta = {
      schema: 1,
      ecosystem,
      sourceUrl: "https://example.invalid/fixture.zip",
      fetchedAt,
      archive: {
        bytes: 1,
        sha256: createHash("sha256").update(ecosystem).digest("hex"),
        lastModified: null,
        etag: null,
      },
      counts: { entries: 0, advisories: 0, malware: 0, withdrawn: 0, skipped: 0 },
      modifiedRange: { min: "2026-01-01T00:00:00Z", max: modifiedMax },
      files: { "advisories.jsonl.gz": { bytes: bytes.length, sha256: "b".repeat(64) } },
    };
    await writeFile(path.join(dir, "meta.json"), JSON.stringify(meta));
  }
  return appData;
}

describe("runDoctor", () => {
  it("shows the built-in PGARD App when no override is set, and exits 0", async () => {
    const captured = createTestIo();
    const code = await runDoctor(createTestContext(captured, createTestDeps()));
    expect(code).toBe(0);
    expect(captured.stdout()).toContain(
      "[ok]   GitHub App: built-in PGARD App (Iv23liKDf0mhnPl2c7zj)",
    );
    expect(captured.stdout()).toContain("All required checks passed.");
    expect(captured.stdout()).toContain("not an authorization");
    expect(captured.stdout()).not.toContain("not set");
  });

  it("shows an override as coming from PGARD_GITHUB_APP_CLIENT_ID", async () => {
    const captured = createTestIo({ env: { PGARD_GITHUB_APP_CLIENT_ID: " Iv23liForkApp " } });
    expect(await runDoctor(createTestContext(captured, createTestDeps()))).toBe(0);
    expect(captured.stdout()).toContain(
      "[ok]   GitHub App: Iv23liForkApp from PGARD_GITHUB_APP_CLIENT_ID (override)",
    );
    expect(captured.stdout()).not.toContain("built-in PGARD App");
  });

  it("treats a whitespace-only override as unset", async () => {
    const captured = createTestIo({ env: { PGARD_GITHUB_APP_CLIENT_ID: "   " } });
    expect(await runDoctor(createTestContext(captured, createTestDeps()))).toBe(0);
    expect(captured.stdout()).toContain(
      "[ok]   GitHub App: built-in PGARD App (Iv23liKDf0mhnPl2c7zj)",
    );
  });

  it("fails the GitHub App row for a malformed override and never prints the value", async () => {
    const store = createInMemoryCredentialStore();
    const captured = createTestIo({ env: { PGARD_GITHUB_APP_CLIENT_ID: '"bad id"' } });
    expect(
      await runDoctor(createTestContext(captured, createTestDeps({ credentialStore: store }))),
    ).toBe(0);
    const stdout = captured.stdout();
    expect(stdout).toContain(
      "[fail] GitHub App: PGARD_GITHUB_APP_CLIENT_ID is set but is not a valid client id; unset it to use the built-in PGARD App. Until then GitHub identity is unverifiable and every scan is blocked.",
    );
    expect(stdout).toContain(
      "[warn] Saved GitHub sign-in: not checked (PGARD_GITHUB_APP_CLIENT_ID is not valid)",
    );
    expect(stdout).not.toContain("bad id");
    expect(stdout).not.toContain("built-in PGARD App (");
    expect(stdout).toContain("1 required check(s) need attention");
  });

  it("shows no advisory data as a warning with the fix, never reads PGARD_ADVISORY_DB", async () => {
    const captured = createTestIo({ env: { PGARD_ADVISORY_DB: "/home/user/private/osv" } });
    expect(await runDoctor(createTestContext(captured, createTestDeps()))).toBe(0);
    const stdout = captured.stdout();
    expect(stdout).toContain(
      "[warn] Advisory data (OSV): none: npm none, Go none; run `pgard advisories update`",
    );
    expect(stdout).not.toContain("/home/user/private/osv");
    expect(stdout).toContain("All required checks passed.");
  });

  it("shows the date for fresh data and marks old data stale", async () => {
    const day = 24 * 60 * 60 * 1000;
    const status = (ageDays: number) => async () => ({
      overall: ageDays >= 7 ? ("stale" as const) : ("fresh" as const),
      ecosystems: (["npm", "Go"] as const).map((ecosystem) => ({
        ecosystem,
        state: ageDays >= 7 ? ("stale" as const) : ("fresh" as const),
        fetchedAt: "2026-10-20T08:00:00.000Z",
        ageDays,
        modifiedMax: null,
        dataAgeDays: null,
        dataVersion: null,
      })),
    });
    const fresh = createTestIo();
    await runDoctor(createTestContext(fresh, createTestDeps({ readAdvisoryStatus: status(2) })));
    expect(fresh.stdout()).toContain(
      "[ok]   Advisory data (OSV): npm 2026-10-20 (2 days old), Go 2026-10-20 (2 days old)",
    );
    const stale = createTestIo();
    await runDoctor(
      createTestContext(
        stale,
        createTestDeps({ readAdvisoryStatus: status(9), now: () => 9 * day }),
      ),
    );
    expect(stale.stdout()).toContain(
      "[warn] Advisory data (OSV): stale: npm 2026-10-20 (9 days old)",
    );
  });

  it("shows the age of the newest record in English and Korean", async () => {
    const status = async () => ({
      overall: "stale" as const,
      ecosystems: [
        {
          ecosystem: "npm" as const,
          state: "stale" as const,
          fetchedAt: "2026-10-27T08:00:00.000Z",
          ageDays: 1,
          modifiedMax: "2024-01-01T00:00:00Z",
          dataAgeDays: 300,
          dataVersion: null,
        },
      ],
    });
    const en = createTestIo();
    await runDoctor(createTestContext(en, createTestDeps({ readAdvisoryStatus: status })));
    expect(en.stdout()).toContain(
      "npm 2026-10-27 (1 day old; newest record 2024-01-01, 300 days old)",
    );
    const ko = createTestIo();
    await runDoctor({
      ...createTestContext(ko, createTestDeps({ readAdvisoryStatus: status })),
      ruleLocale: "ko",
    });
    expect(ko.stdout()).toContain("가장 최근 레코드 2024-01-01, 300일 전");
  });

  it("shows present data with age, version and the store path from a fixture store (EN)", async () => {
    const appData = await fixtureStore("2026-10-27T08:00:00.000Z", "2026-10-26T00:00:00Z");
    const now = Date.parse("2026-10-29T08:00:00.000Z");
    const captured = createTestIo();
    await runDoctor(
      createTestContext(captured, createTestDeps({ appDataDir: appData, now: () => now })),
    );
    const stdout = captured.stdout();
    const version = `1:${createHash("sha256").update("npm").digest("hex").slice(0, 12)}`;
    expect(stdout).toContain(
      `[ok]   Advisory data (OSV): npm 2026-10-27 (2 days old; newest record 2026-10-26, 3 days old; data version ${version})`,
    );
    expect(stdout).toContain(
      `[ok]   Advisory data store: ${path.join(appData, "advisories", "osv")} (present; delete this folder to remove the data)`,
    );
  });

  it("marks a fixture store stale after 7 days and says so in Korean", async () => {
    const appData = await fixtureStore("2026-10-01T08:00:00.000Z", "2026-10-01T00:00:00Z");
    const now = Date.parse("2026-10-29T08:00:00.000Z");
    const captured = createTestIo();
    await runDoctor({
      ...createTestContext(captured, createTestDeps({ appDataDir: appData, now: () => now })),
      ruleLocale: "ko",
    });
    const stdout = captured.stdout();
    expect(stdout).toContain("[warn] 취약점 데이터 (OSV): 오래됨: npm 2026-10-01 (28일 전");
    expect(stdout).toContain("데이터 버전 1:");
    expect(stdout).toContain(
      `[ok]   취약점 데이터 저장 위치: ${path.join(appData, "advisories", "osv")} (있음.`,
    );
  });

  it("reports a missing store with its path in English and Korean", async () => {
    const appData = await mkdtemp(path.join(tmpdir(), "pgard-doctor-"));
    scratch.push(appData);
    const store = path.join(appData, "advisories", "osv");
    const en = createTestIo();
    await runDoctor(createTestContext(en, createTestDeps({ appDataDir: appData })));
    expect(en.stdout()).toContain(
      `[warn] Advisory data store: ${store} (missing; nothing downloaded yet, \`pgard advisories update\` creates it)`,
    );
    const ko = createTestIo();
    await runDoctor({
      ...createTestContext(ko, createTestDeps({ appDataDir: appData })),
      ruleLocale: "ko",
    });
    expect(ko.stdout()).toContain(`[warn] 취약점 데이터 저장 위치: ${store} (없음.`);
    expect(ko.stdout()).toContain("없음: npm 없음, Go 없음");
  });

  it("says where advisory data cannot be stored when there is no home directory", async () => {
    const captured = createTestIo();
    await runDoctor(createTestContext(captured, createTestDeps({ appDataDir: null })));
    expect(captured.stdout()).toContain("[warn] Advisory data (OSV): no home directory found");
  });

  it("requires a Node.js release with the October 2026 security fixes", () => {
    for (const ok of ["22.23.4", "22.24.0", "24.22.1", "24.23.0", "26.12.1", "26.13.0", "28.0.0"]) {
      expect(isSupportedNodeVersion(ok), ok).toBe(true);
    }
    for (const bad of [
      "22.12.0",
      "22.23.3",
      "23.11.0",
      "24.22.0",
      "24.9.9",
      "25.9.0",
      "26.12.0",
      "26.3.0",
      "20.19.0",
      "",
    ]) {
      expect(isSupportedNodeVersion(bad), bad).toBe(false);
    }
  });
});
