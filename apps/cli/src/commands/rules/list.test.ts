import { describe, expect, it } from "vitest";
import { createTestContext, createTestDeps, createTestIo } from "../../test-support.js";
import { RULE_CRITERIA_VERSION, runRulesList } from "./list.js";

describe("runRulesList", () => {
  it("shows the criteria version, web rules, advisory status and unsupported areas", () => {
    const captured = createTestIo();
    expect(runRulesList(createTestContext(captured, createTestDeps()), null)).toBe(0);
    const stdout = captured.stdout();
    expect(stdout).toContain(`detection criteria ${RULE_CRITERIA_VERSION}`);
    expect(stdout).toContain("PG-WEB-013");
    expect(stdout).toContain("Advisory database status: missing");
    expect(stdout).toContain("Direct database connections");
  });
});
