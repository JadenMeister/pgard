import { describe, expect, it } from "vitest";
import {
  assertConfirmedWebTarget,
  buildLoopbackOrigin,
  InvalidTargetError,
  parseAllowedLoopbackUrl,
  parsePort,
} from "./target.js";

describe("parsePort", () => {
  it("accepts integers from 1 to 65535", () => {
    expect(parsePort("1")).toBe(1);
    expect(parsePort("3000")).toBe(3000);
    expect(parsePort("65535")).toBe(65535);
  });

  it.each([
    "0",
    "65536",
    "-1",
    "+80",
    "3000.0",
    "0x50",
    " 80",
    "80 ",
    "",
    "abc",
    "127.0.0.1:80",
    "1e3",
  ])("rejects %j", (value) => {
    expect(() => parsePort(value)).toThrow(InvalidTargetError);
  });
});

describe("parseAllowedLoopbackUrl", () => {
  const options = { port: 3000 };

  it("accepts http://127.0.0.1 on the same port, including relative paths", () => {
    expect(parseAllowedLoopbackUrl("http://127.0.0.1:3000/a", undefined, options)?.pathname).toBe(
      "/a",
    );
    expect(parseAllowedLoopbackUrl("/b?x=1", "http://127.0.0.1:3000/", options)?.pathname).toBe(
      "/b",
    );
  });

  it.each([
    "http://localhost:3000/",
    "http://example.com:3000/",
    "http://10.0.0.1:3000/",
    "http://127.0.0.1:3001/",
    "http://127.0.0.1/",
    "https://127.0.0.1:3000/",
    "file:///etc/passwd",
    "http://user:pass@127.0.0.1:3000/",
    "//evil.example:3000/",
    "http://[::1]:3000/",
    "javascript:alert(1)",
  ])("rejects %s", (raw) => {
    expect(parseAllowedLoopbackUrl(raw, "http://127.0.0.1:3000/", options)).toBeNull();
  });

  it("accepts [::1] only when explicitly allowed", () => {
    expect(
      parseAllowedLoopbackUrl("http://[::1]:3000/", undefined, {
        port: 3000,
        isIpv6LoopbackAllowed: true,
      }),
    ).not.toBeNull();
  });
});

describe("assertConfirmedWebTarget", () => {
  it("accepts a confirmed loopback target", () => {
    expect(() =>
      assertConfirmedWebTarget({
        port: 8080,
        origin: buildLoopbackOrigin(8080),
        title: null,
        confirmedByUser: true,
      }),
    ).not.toThrow();
  });

  it("rejects unconfirmed, mismatched or non-loopback targets", () => {
    const unconfirmed = {
      port: 8080,
      origin: "http://127.0.0.1:8080",
      title: null,
      confirmedByUser: false,
    };
    expect(() => assertConfirmedWebTarget(unconfirmed as never)).toThrow(InvalidTargetError);
    expect(() =>
      assertConfirmedWebTarget({
        port: 8080,
        origin: "http://example.com:8080",
        title: null,
        confirmedByUser: true,
      }),
    ).toThrow(InvalidTargetError);
    expect(() =>
      assertConfirmedWebTarget({
        port: 8080,
        origin: "http://127.0.0.1:8081",
        title: null,
        confirmedByUser: true,
      }),
    ).toThrow(InvalidTargetError);
    expect(() =>
      assertConfirmedWebTarget({
        port: 0,
        origin: "http://127.0.0.1:0",
        title: null,
        confirmedByUser: true,
      }),
    ).toThrow(InvalidTargetError);
  });
});
