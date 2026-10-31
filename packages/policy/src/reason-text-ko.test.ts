import { describe, expect, it } from "vitest";
import { authorizationReasonText } from "@pgard/findings";
import {
  contributionGuidance,
  notFoundAccessReason,
  notFoundAllRepositoriesReason,
} from "./checks.js";
import { REPOSITORY_CHANGED_REASON } from "./types.js";

/** The reasons the policy builds from exported helpers must have a Korean text (#449). */
describe("Korean text of the policy's exported reasons", () => {
  it.each([
    ["repository changed", REPOSITORY_CHANGED_REASON],
    ["404 access", notFoundAccessReason("acme/app")],
    ["404 all repositories", notFoundAllRepositoriesReason("acme/app")],
    [
      "no local commits",
      `No local commits were found to check for a contribution. ${contributionGuidance("main")}`,
    ],
  ])("translates %s", (_name, reason) => {
    const shown = authorizationReasonText(reason, "ko");
    expect(shown.translated).toBe(true);
    expect(shown.text).toMatch(/[가-힣]/);
  });
});
