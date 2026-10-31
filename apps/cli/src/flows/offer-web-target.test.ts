import type { ScanRequest } from "@pgard/findings";
import type { PortDiscoveryResult, ProbeOptions, ServiceIdentity } from "@pgard/http-local";
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
import { UserCancelledError } from "../ui/components/prompts.js";
import { offerWebTarget, shouldOfferWebTarget } from "./offer-web-target.js";
import { TIME_FACTOR } from "../../../../tests/support/timing.js";

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
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

interface SetupOptions {
  ports?: number[];
  keys?: Parameters<typeof scriptedKeys>[0];
  env?: Record<string, string>;
  isTTY?: boolean;
  discover?: () => Promise<PortDiscoveryResult>;
  probe?: (port: number, options?: ProbeOptions) => Promise<ServiceIdentity>;
  blocked?: boolean;
  /** Default true: a sign-in already exists, so the offer may run the gate. */
  hasSession?: boolean;
  verifyDelayMs?: number;
  title?: string | null;
  processName?: string;
}

function setup(options: SetupOptions = {}) {
  const captured = createTestIo({ isTTY: options.isTTY ?? true, env: options.env ?? {} });
  const requests: ScanRequest[] = [];
  let gateRuns = 0;
  const discoverListeningPorts = vi.fn(
    options.discover ??
      (async () => {
        const found = discovery(...(options.ports ?? [3000]));
        if (options.processName !== undefined) {
          for (const entry of found.ports) entry.processName = options.processName;
        }
        return found;
      }),
  );
  const probeLocalService = vi.fn(
    options.probe ??
      (async (port: number) =>
        identityFor(
          port,
          options.title !== undefined ? options.title : port === 3000 ? "Acme Shop" : null,
        )),
  );
  const base = createTestDeps();
  const deps = createTestDeps({
    discoverListeningPorts,
    probeLocalService,
    createSessionProvider: () =>
      Object.assign(async () => ({}) as never, {
        existing: async () => (options.hasSession === false ? null : ({} as never)),
      }) as never,
    verifyProject: async (...args: Parameters<typeof base.verifyProject>) => {
      gateRuns += 1;
      if (options.verifyDelayMs !== undefined) await sleep(options.verifyDelayMs);
      const outcome = await base.verifyProject(...args);
      return options.blocked === true ? { ...outcome, summary: BLOCKED } : outcome;
    },
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
  return {
    captured,
    requests,
    discoverListeningPorts,
    probeLocalService,
    context,
    gateRuns: () => gateRuns,
  };
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

  it("keeps a port that answers when another one never answers", async () => {
    const t = setup({
      ports: [3000, 5555],
      keys: ["y"],
      probe: (port) =>
        port === 5555 ? new Promise(() => undefined) : Promise.resolve(identityFor(port, "Good")),
    });
    const started = Date.now();
    expect(await offerWebTarget(t.context, { budgetMs: 60 })).toBe(3000);
    expect(Date.now() - started).toBeLessThan(1000 * TIME_FACTOR);
    expect(t.captured.stdout()).toContain("Good");
  });

  it("keeps a port that answers when another one is a slow-loris", async () => {
    const t = setup({
      ports: [4000, 3000],
      keys: ["y"],
      probe: async (port) => {
        if (port === 4000) {
          await sleep(400);
          return identityFor(4000, "Slow");
        }
        return identityFor(port, "Fast");
      },
    });
    expect(await offerWebTarget(t.context, { budgetMs: 60 })).toBe(3000);
    expect(t.captured.stdout()).not.toContain("Slow");
  });

  it("gives the probes their full budget however long the gate takes", async () => {
    const t = setup({
      verifyDelayMs: 150,
      keys: ["return"],
      probe: async (port) => {
        await sleep(60);
        return identityFor(port, "Late");
      },
    });
    await runScanCommand(t.context, DEFAULT_SCAN);
    expect(t.captured.stdout()).toContain("Also scan http://127.0.0.1:3000 (Late)");
  });

  it("passes a timeout and an abort signal to every probe, and aborts them afterwards", async () => {
    const seen: ProbeOptions[] = [];
    const t = setup({
      keys: ["return"],
      probe: async (port, options) => {
        seen.push(options ?? {});
        return identityFor(port, "Acme");
      },
    });
    await offerWebTarget(t.context, { budgetMs: 500 });
    expect(seen[0]?.timeoutMs).toBe(500);
    expect(seen[0]?.signal?.aborted).toBe(true);
  });

  it("treats Esc as no", async () => {
    expect(await offerWebTarget(setup({ keys: ["escape"] }).context)).toBeNull();
    const several = setup({ ports: [3000, 5173], keys: ["escape"] });
    expect(await offerWebTarget(several.context)).toBeNull();
  });

  it("cancels the scan (UserCancelledError) on Ctrl+C then y at the offer", async () => {
    const t = setup({ keys: [CTRL_C, "y"] });
    await expect(runScanCommand(t.context, DEFAULT_SCAN)).rejects.toBeInstanceOf(
      UserCancelledError,
    );
    expect(t.requests).toHaveLength(0);
  });

  it("keeps asking when Ctrl+C is not confirmed", async () => {
    const t = setup({ keys: [CTRL_C, "n", "return"] });
    expect(await offerWebTarget(t.context)).toBeNull();
    expect(t.captured.stdout()).toContain("Cancel and exit?");
  });

  it("does not ask when a cancel was confirmed while looking", async () => {
    const t = setup({ keys: ["return"] });
    const controller = new AbortController();
    controller.abort();
    await expect(
      offerWebTarget({ ...t.context, signal: controller.signal }),
    ).rejects.toBeInstanceOf(UserCancelledError);
    expect(t.captured.stdout()).not.toContain("Also scan");
  });

  it("strips control sequences from the title and the process name in the label", async () => {
    const hostile = "Evil\u001b[31m\u0007\u009b2J\u001b]0;x\u0007Shop";
    const cases = [
      setup({ title: hostile, keys: ["return"] }),
      setup({ title: null, processName: hostile, keys: ["return"] }),
    ];
    for (const t of cases) {
      await offerWebTarget(t.context);
      const text = t.captured.stdout();
      expect(text).toContain("Also scan http://127.0.0.1:3000");
      expect(text).not.toMatch(/[\u001b\u0007\u009b]/);
    }
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

  it("never offers when the scan only sets the baseline from the current scan", async () => {
    const t = setup({ keys: ["y"] });
    await runScanCommand(t.context, { ...DEFAULT_SCAN, setBaseline: true });
    expect(t.discoverListeningPorts).not.toHaveBeenCalled();
    expect(t.captured.stdout()).not.toContain("Also scan");
  });

  it("does not probe any port when authorization does not allow the project", async () => {
    const t = setup({ blocked: true });
    await runScanCommand(t.context, DEFAULT_SCAN);
    expect(t.probeLocalService).not.toHaveBeenCalled();
    expect(t.captured.stdout()).not.toContain("Also scan");
  });

  it("is skipped, without running the gate, when no sign-in exists yet", async () => {
    const t = setup({ hasSession: false });
    await runScanCommand(t.context, DEFAULT_SCAN);
    expect(t.probeLocalService).not.toHaveBeenCalled();
    expect(t.gateRuns()).toBe(0); // runScan is stubbed, so no gate ran at all
    expect(t.captured.stdout()).not.toContain("Also scan");
  });

  it("opens the panel view after a declined offer", async () => {
    const t = setup({ keys: ["return", "escape"] });
    await runScanCommand(t.context, DEFAULT_SCAN);
    expect(t.captured.stdout()).toContain("\u001b[?1049h");
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
