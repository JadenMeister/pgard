import { describe, expect, it } from "vitest";
import { describeStoredSignIn, SIGN_OUT_HINTS, SIGN_OUT_LABELS } from "./sign-in-text";

describe("dashboard sign-in texts", () => {
  it("labels both sign-out actions by what they do to the OS keychain", () => {
    expect(SIGN_OUT_LABELS.sessionOnly).toMatch(/dashboard session.*keep keychain/i);
    expect(SIGN_OUT_LABELS.removeStored).toMatch(/remove from OS keychain/i);
    expect(SIGN_OUT_HINTS.sessionOnly).toMatch(/stays/);
    expect(SIGN_OUT_HINTS.removeStored).toMatch(/deletes/);
  });

  it("describes the stored sign-in with the login only", () => {
    expect(describeStoredSignIn({ status: "stored", login: "octo" })).toContain(
      "octo, saved in the OS keychain",
    );
    expect(describeStoredSignIn({ status: "none" })).toContain("asks for a device code");
    expect(describeStoredSignIn({ status: "unavailable", reason: "locked" })).toContain(
      "kept in memory until the dashboard stops",
    );
    expect(describeStoredSignIn({ status: "unknown" })).toBeNull();
  });
});
