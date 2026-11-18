import { NETWORK_CAUSE_CODES } from "@pgard/dependencies";
import { describe, expect, it } from "vitest";
import { CONNECTION_CAUSE_CODES, TLS_CAUSE_CODES } from "./index.js";

describe("network cause whitelist", () => {
  it("is the same list in the advisories download and in the GitHub clients", () => {
    expect([...NETWORK_CAUSE_CODES].sort()).toEqual(
      [...TLS_CAUSE_CODES, ...CONNECTION_CAUSE_CODES].sort(),
    );
  });
});
