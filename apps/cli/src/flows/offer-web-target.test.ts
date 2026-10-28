import type { ScanRequest } from "@pgard/findings";
import type { PortDiscoveryResult, ServiceIdentity } from "@pgard/http-local";
import { describe, expect, it, vi } from "vitest";
import { runScanCommand } from "../commands/scan/index.js";
import {
  BLOCKED,
  createTestContext,
  createTestDeps,
  createTestIo,
  HTTP_IDENTITY,
  scriptedKeys,
  testResult,
} from "../test-support.js";
import { offerWebTarget, shouldOfferWebTarget } from "./offer-web-target.js";

function discovery(...ports: number[]): PortDiscoveryResult {
  return {
    ports: ports.map((port) => ({ port, processName: "node" })),
    method: "lsof",
    isComplete: false,
    isAvailable: true,
    note: null,
  };
}

function identityFor(port: number, title: string | null): ServiceIdentity {
  return { ...HTTP_IDENTITY, port, url: `http://127.0.0.1:${port}/`, title };
}

const DEFAULT_SCAN = { variant: "default", port: null, report: null } as const;
const CTRL_C = { name: "c", ctrl: true, sequence: undefined } as const;

interface SetupOptions {
  ports?: number[];
  keys?: Parameters<typeof scriptedKeys>[0];
  env?: Record<string, string>;
  isTTY?: boolean;
  discover?: () => Promise<PortDiscoveryResult>;
  probe?: (port: number) => Promise<ServiceIdentity>;
  blocked?: boolean;
}

function setup(options: SetupOptions = {}) {
  const captured = createTestIo({ isTTY: options.isTTY ?? true, env: options.env ?? {} });
  const requests: ScanRequest[] = [];
  const discoverListeningPorts = vi.fn(
    options.discover ?? (async () => discovery(...(options.ports ?? [3000]))),
  );
  const probeLocalService = vi.fn(
    options.probe ??
      (async (port: number) => identityFor(port, port === 3000 ? "Acme Shop" : null)),
  );
  const base = createTestDeps();
  const deps = createTestDeps({
    discoverListeningPorts,
    probeLocalService,
    ...(options.blocked === true
      ? {
          verifyProject: async (...args: Parameters<typeof base.verifyProject>) => {
            const outcome = await base.verifyProject(...args);
            return { ...outcome, summary: BLOCKED };
          },
        }
      : {}),
    runScan: async (request) => {
      requests.push(request);
      return testResult({ requestedScopes: request.scopes });
    },
  });
  const context = createTestContext(
    captured,
    deps,
    options.isTTY === false ? null : scriptedKeys(options.keys ?? []),
  );
  return { captured, requests, discoverListeningPorts, probeLocalService, context };
}

describe("interactive scan offers a detected local web service", () => {
  it("offers nothing and scans normally when no server listens", async () => {
    const t = setup({ ports: [] });
    await runScanCommand(t.context, DEFAULT_SCAN);
    expect(t.captured.stdout()).not.toContain("Also scan");
    expect(t.requests[0]?.scopes).toEqual(["code", "history"]);
    expect(t.probeLocalService).not.toHaveBeenCalled();
  });

  it("asks about a single server and keeps code and history only on N", async () => {
    const t = setup({ keys: ["return"] });
    await runScanCommand(t.context, DEFAULT_SCAN);
    expect(t.captured.stdout()).toContain("Also scan http://127.0.0.1:3000 (Acme Shop)");
    expect(t.captured.stdout()).toContain("[y/N]");
    expect(t.requests[0]).toMatchObject({ scopes: ["code", "history"], webTarget: null });
  });

  it("on y still shows the identity and asks the same explicit confirmation as --port", async () => {
    const t = setup({ keys: ["y", "y"] });
    await runScanCommand(t.context, DEFAULT_SCAN);
    expect(t.captured.stdout()).toContain("Is this the current project's service?");
    expect(t.captured.stdout()).toContain("Title:  Acme Shop");
    expect(t.requests[0]).toMatchObject({
      scopes: ["code", "history", "web"],
      webTarget: { port: 3000, origin: "http://127.0.0.1:3000", confirmedByUser: true },
    });
  });

  it("does not scan the web when the chosen target is not confirmed", async () => {
    // y to the offer, Enter (N) at the confirmation, then Esc on the port list.
    const t = setup({ keys: ["y", "return", "escape"] });
    await runScanCommand(t.context, DEFAULT_SCAN);
    expect(t.requests[0]).toMatchObject({ scopes: ["code", "history"], webTarget: null });
  });

  it("lists several servers with a none choice first, and Enter on it means no", async () => {
    const t = setup({ ports: [3000, 5173], keys: ["return"] });
    await runScanCommand(t.context, DEFAULT_SCAN);
    const text = t.captured.stdout();
    expect(text).toContain("http://127.0.0.1:3000 (Acme Shop)");
    expect(text).toContain("http://127.0.0.1:5173 (node)");
    expect(text.indexOf("No, do not scan")).toBeLessThan(text.indexOf("127.0.0.1:3000"));
    expect(t.requests[0]).toMatchObject({ scopes: ["code", "history"], webTarget: null });
  });

  it("scans the chosen one of several servers, after the confirmation", async () => {
    const t = setup({ ports: [3000, 5173], keys: ["down", "down", "return", "y"] });
    await runScanCommand(t.context, DEFAULT_SCAN);
    expect(t.requests[0]).toMatchObject({
      scopes: ["code", "history", "web"],
      webTarget: { port: 5173 },
    });
  });

  it("does not wait for a discovery that hangs, and survives one that fails", async () => {
    const hung = setup({ discover: () => new Promise(() => undefined) });
    expect(await offerWebTarget(hung.context, { budgetMs: 30 })).toBeNull();
    const failed = setup({ discover: () => Promise.reject(new Error("lsof failed")) });
    expect(await runScanCommand(failed.context, DEFAULT_SCAN)).toBe(0);
    expect(failed.requests[0]?.scopes).toEqual(["code", "history"]);
  });

  it("does not wait for probes that hang", async () => {
    const t = setup({ probe: () => new Promise(() => undefined) });
    expect(await offerWebTarget(t.context, { budgetMs: 30 })).toBeNull();
  });

  it("treats Esc, and Ctrl+C then y, as no", async () => {
    expect(await offerWebTarget(setup({ keys: [CTRL_C, "y"] }).context)).toBeNull();
    expect(await offerWebTarget(setup({ keys: ["escape"] }).context)).toBeNull();
    expect(
      await offerWebTarget(setup({ ports: [3000, 5173], keys: ["escape"] }).context),
    ).toBeNull();
  });

  it("scans without web after Ctrl+C at the offer", async () => {
    const t = setup({ keys: [CTRL_C, "y"] });
    await runScanCommand(t.context, DEFAULT_SCAN);
    expect(t.requests[0]).toMatchObject({ scopes: ["code", "history"], webTarget: null });
  });

  it("does not look for servers without a terminal", async () => {
    const t = setup({ isTTY: false });
    await runScanCommand(t.context, DEFAULT_SCAN);
    expect(t.discoverListeningPorts).not.toHaveBeenCalled();
    expect(t.requests[0]?.scopes).toEqual(["code", "history"]);
  });

  it.each<Record<string, string>>([{ CI: "true" }, { GITHUB_ACTIONS: "true" }, { TERM: "dumb" }])(
    "does not offer in automation (%o)",
    async (env) => {
      const t = setup({ env });
      await runScanCommand(t.context, DEFAULT_SCAN);
      expect(t.discoverListeningPorts).not.toHaveBeenCalled();
      expect(t.requests[0]?.scopes).toEqual(["code", "history"]);
    },
  );

  it("does not offer with --port (the explicit target wins)", async () => {
    const t = setup({ keys: ["y"] });
    await runScanCommand(t.context, { ...DEFAULT_SCAN, port: 3000 });
    expect(t.captured.stdout()).not.toContain("Also scan");
    expect(t.requests[0]?.scopes).toEqual(["code", "history"]);
  });

  it.each(["json", "sarif"] as const)("does not offer with --format %s", async (format) => {
    const t = setup();
    await runScanCommand(t.context, { ...DEFAULT_SCAN, format });
    expect(t.discoverListeningPorts).not.toHaveBeenCalled();
  });

  it.each(["code", "history"] as const)(
    "does not offer for the explicit scope %s",
    async (variant) => {
      const t = setup({ keys: ["y", "y"] });
      await runScanCommand(t.context, { variant, port: null, report: null });
      expect(t.discoverListeningPorts).not.toHaveBeenCalled();
    },
  );

  it("does not probe any port when authorization does not allow the project", async () => {
    const t = setup({ blocked: true, keys: [] });
    await runScanCommand(t.context, DEFAULT_SCAN);
    expect(t.probeLocalService).not.toHaveBeenCalled();
    expect(t.captured.stdout()).not.toContain("Also scan");
  });

  it("asks in Korean", async () => {
    const t = setup({ keys: ["return"] });
    await offerWebTarget({ ...t.context, ruleLocale: "ko" });
    expect(t.captured.stdout()).toContain("함께 검사할까요");
  });

  it("is eligible only for the bare scan in an interactive terminal", () => {
    const t = setup();
    const base = { isDefaultScope: true, hasPort: false, isMachineFormat: false };
    expect(shouldOfferWebTarget(t.context, base)).toBe(true);
    expect(shouldOfferWebTarget(t.context, { ...base, isDefaultScope: false })).toBe(false);
    expect(shouldOfferWebTarget(t.context, { ...base, hasPort: true })).toBe(false);
    expect(shouldOfferWebTarget(t.context, { ...base, isMachineFormat: true })).toBe(false);
  });
});
