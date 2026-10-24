import { describe, expect, it } from "vitest";
import { createDefaultDeps } from "../deps.js";
import { createTestContext, createTestDeps, createTestIo } from "../test-support.js";
import { isSupportedNodeVersion, runDoctor } from "./doctor.js";

describe("runDoctor", () => {
  it("reports a missing client id and still exits 0 because the diagnosis completed", async () => {
    const captured = createTestIo();
    const code = await runDoctor(createTestContext(captured, createTestDeps()));
    expect(code).toBe(0);
    expect(captured.stdout()).toContain("1 required check(s) need attention");
    expect(captured.stdout()).toContain("[fail] PGARD_GITHUB_APP_CLIENT_ID: not set");
    expect(captured.stdout()).toContain("not an authorization");
  });

  it("never prints the client id value and exits 0 when required checks pass", async () => {
    const captured = createTestIo({ env: { PGARD_GITHUB_APP_CLIENT_ID: "Iv23liSecretLooking" } });
    expect(await runDoctor(createTestContext(captured, createTestDeps()))).toBe(0);
    expect(captured.stdout()).not.toContain("Iv23liSecretLooking");
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
