import { describe, expect, it } from "vitest";
import { formatExpiry, isGitHubUrl } from "./device-code";

describe("isGitHubUrl", () => {
  it("only accepts https github.com links", () => {
    expect(isGitHubUrl("https://github.com/login/device")).toBe(true);
    expect(isGitHubUrl("javascript:alert(1)")).toBe(false);
    expect(isGitHubUrl("http://github.com/login/device")).toBe(false);
    expect(isGitHubUrl("https://github.com.evil.example/")).toBe(false);
    expect(isGitHubUrl("https://evil.example/github.com")).toBe(false);
    expect(isGitHubUrl("not a url")).toBe(false);
  });

  it("formats the expiry in minutes", () => {
    expect(formatExpiry(900)).toBe("Expires in about 15 min.");
    expect(formatExpiry(10)).toBe("Expires in about 1 min.");
  });
});
