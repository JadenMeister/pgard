import { describe, expect, it } from "vitest";
import { createTestContext, createTestDeps, createTestIo } from "../test-support.js";
import { isSupportedNodeVersion, runDoctor } from "./doctor.js";

describe("runDoctor", () => {
  it("reports missing client id without printing values and exits 4", async () => {
    const captured = createTestIo();
    const code = await runDoctor(createTestContext(captured, createTestDeps()));
    expect(code).toBe(4);
    expect(captured.stdout()).toContain("[fail] PGARD_GITHUB_APP_CLIENT_ID: not set");
    expect(captured.stdout()).toContain("not an authorization");
  });

  it("never prints the client id value and exits 0 when required checks pass", async () => {
    const captured = createTestIo({ env: { PGARD_GITHUB_APP_CLIENT_ID: "Iv23liSecretLooking" } });
    expect(await runDoctor(createTestContext(captured, createTestDeps()))).toBe(0);
    expect(captured.stdout()).not.toContain("Iv23liSecretLooking");
  });

  it("checks the Node.js version", () => {
    expect(isSupportedNodeVersion("22.12.0")).toBe(true);
    expect(isSupportedNodeVersion("22.11.9")).toBe(false);
    expect(isSupportedNodeVersion("26.3.0")).toBe(true);
    expect(isSupportedNodeVersion("20.0.0")).toBe(false);
  });
});
