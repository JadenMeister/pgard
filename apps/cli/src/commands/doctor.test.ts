import { createInMemoryCredentialStore } from "@pgard/scan-core";
import { describe, expect, it } from "vitest";
import { createTestContext, createTestDeps, createTestIo } from "../test-support.js";
import { isSupportedNodeVersion, runDoctor } from "./doctor.js";

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

  it("has no advisory database row and never reads PGARD_ADVISORY_DB", async () => {
    const captured = createTestIo({ env: { PGARD_ADVISORY_DB: "/home/user/private/osv" } });
    expect(await runDoctor(createTestContext(captured, createTestDeps()))).toBe(0);
    const stdout = captured.stdout();
    expect(stdout).not.toMatch(/advisory/i);
    expect(stdout).not.toContain("/home/user/private/osv");
    expect(stdout).toContain("All required checks passed.");
  });

  it("checks the Node.js version", () => {
    expect(isSupportedNodeVersion("22.12.0")).toBe(true);
    expect(isSupportedNodeVersion("22.11.9")).toBe(false);
    expect(isSupportedNodeVersion("26.3.0")).toBe(true);
    expect(isSupportedNodeVersion("20.0.0")).toBe(false);
  });
});
