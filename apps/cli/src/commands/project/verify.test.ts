import { describe, expect, it } from "vitest";
import { BLOCKED, createTestContext, createTestDeps, createTestIo } from "../../test-support.js";
import { runProjectVerify } from "./verify.js";

describe("runProjectVerify", () => {
  it("shows each check and exits 3 when blocked", async () => {
    const captured = createTestIo();
    const code = await runProjectVerify(
      createTestContext(
        captured,
        createTestDeps({
          verifyProject: async () => ({ summary: BLOCKED, repo: "owner/name", revision: null }),
        }),
      ),
    );
    expect(code).toBe(3);
    const stdout = captured.stdout();
    expect(stdout).toContain("[passed] repository");
    expect(stdout).toContain("[unverifiable] owner approval: Not evaluated.");
    expect(stdout).toContain("not stored");
  });

  it("exits 0 when allowed", async () => {
    const captured = createTestIo({ env: { PGARD_GITHUB_APP_CLIENT_ID: "Iv23liExample" } });
    expect(await runProjectVerify(createTestContext(captured, createTestDeps()))).toBe(0);
    expect(captured.stderr()).not.toContain("Hint");
  });
});
