import { describe, expect, it } from "vitest";
import { hasInviteToken, hasSessionToken, takeTokenFromLocation } from "./client";

function fakeHistory(replaced: string[]): History {
  return {
    replaceState: (_state: unknown, _title: string, url: string) => replaced.push(url),
  } as unknown as History;
}

describe("takeTokenFromLocation", () => {
  it("reads the token from the fragment and removes it from the address bar", () => {
    const replaced: string[] = [];
    const location = {
      hash: "#token=abcdefghijklmnopqrstuvwxyz012345",
      pathname: "/",
      search: "",
    } as Location;
    expect(takeTokenFromLocation(location, fakeHistory(replaced))).toBe(
      "abcdefghijklmnopqrstuvwxyz012345",
    );
    expect(hasInviteToken()).toBe(true);
    // The URL token is never used as the session itself.
    expect(hasSessionToken()).toBe(false);
    expect(replaced).toEqual(["/"]);
  });

  it("rejects malformed tokens and still clears the fragment", () => {
    const replaced: string[] = [];
    for (const hash of [
      "#token=<script>",
      "#token=short",
      "",
      "#other=abcdefghijklmnopqrstuvwxyz",
    ]) {
      const location = { hash, pathname: "/", search: "" } as Location;
      expect(takeTokenFromLocation(location, fakeHistory(replaced))).toBeNull();
    }
    expect(hasInviteToken()).toBe(false);
    expect(hasSessionToken()).toBe(false);
    expect(replaced).toEqual(["/", "/", "/", "/"]);
  });
});
