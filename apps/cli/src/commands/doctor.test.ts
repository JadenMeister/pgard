import { createInMemoryCredentialStore } from "@pgard/scan-core";
import { describe, expect, it } from "vitest";
import { createDefaultDeps } from "../deps.js";
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

  it("shows a missing advisory database as a [warn] row that does not fail the diagnosis", async () => {
    const captured = createTestIo({ env: { PGARD_GITHUB_APP_CLIENT_ID: "Iv23liClient" } });
    expect(await runDoctor(createTestContext(captured, createTestDeps()))).toBe(0);
    const stdout = captured.stdout();
    expect(stdout).toContain(
      "[warn] Advisory database: missing - version none, updated never - No advisory database is configured.",
    );
    expect(stdout).toContain("All required checks passed.");
  });

  it("shows stale and ok advisory databases with version and update time, never the path", async () => {
    const dbPath = "/home/user/private/osv-export.json";
    const run = async (status: "ok" | "stale"): Promise<string> => {
      const captured = createTestIo({ env: { PGARD_ADVISORY_DB: dbPath } });
      const deps = createTestDeps({
        readAdvisoryDbStatus: async (env) => ({
          status,
          version: env.PGARD_ADVISORY_DB === undefined ? null : "osv-42",
          updatedAt: "2026-10-01T00:00:00.000Z",
          advisoryCount: 42,
          note: status === "ok" ? "42 advisories, updated 2026-10-01." : "Advisory data is stale.",
        }),
      });
      await runDoctor(createTestContext(captured, deps));
      return captured.stdout();
    };
    const ok = await run("ok");
    const stale = await run("stale");
    expect(ok).toContain(
      "[ok]   Advisory database: ok - version osv-42, updated 2026-10-01T00:00:00.000Z - 42 advisories, updated 2026-10-01.",
    );
    expect(stale).toContain("[warn] Advisory database: stale - version osv-42");
    expect(ok).not.toContain(dbPath);
    expect(stale).not.toContain(dbPath);
  });

  it("shows a not fully validated ok database as [warn] unverified with its note, no version", async () => {
    const captured = createTestIo({ env: { PGARD_ADVISORY_DB: "/home/user/private/osv" } });
    const deps = createTestDeps({
      readAdvisoryDbStatus: async () => ({
        status: "ok",
        version: null,
        updatedAt: null,
        advisoryCount: 0,
        note: "A sample record is valid OSV; version and freshness were not verified.",
        validated: false,
      }),
    });
    await runDoctor(createTestContext(captured, deps));
    const stdout = captured.stdout();
    expect(stdout).toContain(
      "[warn] Advisory database: unverified - not fully validated - A sample record is valid OSV; version and freshness were not verified.",
    );
    expect(stdout).not.toContain("version none");
    expect(stdout).not.toContain("/home/user/private/osv");
  });

  it("uses the advisory package for the default advisory status (missing when unset)", async () => {
    const status = await createDefaultDeps().readAdvisoryDbStatus({});
    expect(status.status).toBe("missing");
    expect(status.version).toBeNull();
  });

  it("checks the Node.js version", () => {
    expect(isSupportedNodeVersion("22.12.0")).toBe(true);
    expect(isSupportedNodeVersion("22.11.9")).toBe(false);
    expect(isSupportedNodeVersion("26.3.0")).toBe(true);
    expect(isSupportedNodeVersion("20.0.0")).toBe(false);
  });
});
