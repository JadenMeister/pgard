import type { PortDiscoveryResult, ProjectSignals, ServiceIdentity } from "@pgard/http-local";
import { describe, expect, it } from "vitest";
import {
  createTestContext,
  createTestDeps,
  createTestIo,
  HTTP_IDENTITY,
  scriptedKeys,
} from "../test-support.js";
import { findWebTargets, WEB_OFFER_BUDGET_MS } from "./offer-web-target.js";
import { selectLocalPort } from "./select-local-port.js";

const PROJECT: ProjectSignals = {
  folderName: "shop",
  repo: "acme/shop",
  manifestNames: ["shop"],
  dependencies: ["next", "react"],
};

function identity(
  port: number,
  title: string | null,
  technologies: string[] = [],
): ServiceIdentity {
  return {
    ...HTTP_IDENTITY,
    port,
    url: `http://127.0.0.1:${port}/`,
    title,
    inferredTechnologies: technologies,
  };
}

function discovery(...ports: number[]): PortDiscoveryResult {
  return {
    ports: ports.map((port) => ({ port, processName: "node" })),
    method: "lsof",
    isComplete: false,
    isAvailable: true,
    note: null,
  };
}

function setup(options: {
  services: Record<number, ServiceIdentity>;
  keys: Parameters<typeof scriptedKeys>[0];
  locale?: "en" | "ko";
}) {
  const captured = createTestIo({ isTTY: true });
  const deps = createTestDeps({
    probeLocalService: async (port) => options.services[port] ?? identity(port, null),
    discoverListeningPorts: async () => discovery(...Object.keys(options.services).map(Number)),
  });
  const context = {
    ...createTestContext(captured, deps, scriptedKeys(options.keys)),
    ...(options.locale === undefined ? {} : { ruleLocale: options.locale }),
  };
  return { captured, context };
}

const WARNING_EN =
  "This service doesn't look related to this project (service: 'Grafana', project: 'shop').";
const WARNING_KO =
  "이 서비스는 현재 프로젝트와 관련 없어 보입니다 (서비스: 'Grafana', 프로젝트: 'shop').";

describe("the y/N confirmation warns when the service looks unrelated", () => {
  it("prints one warning line before the question for an unlikely service, default stays N", async () => {
    const t = setup({ services: { 3000: identity(3000, "Grafana") }, keys: ["return", "escape"] });
    const selection = await selectLocalPort(t.context, 3000, PROJECT);
    const text = t.captured.stdout();
    expect(text).toContain(WARNING_EN);
    expect(text.indexOf(WARNING_EN)).toBeLessThan(
      text.indexOf("Is this the current project's service?"),
    );
    expect(selection.kind).toBe("back");
  });

  it("still lets the user answer y", async () => {
    const t = setup({ services: { 3000: identity(3000, "Grafana") }, keys: ["y"] });
    const selection = await selectLocalPort(t.context, 3000, PROJECT);
    expect(t.captured.stdout()).toContain(WARNING_EN);
    expect(selection).toMatchObject({ kind: "confirmed", target: { port: 3000 } });
  });

  it("says it in Korean", async () => {
    const t = setup({
      services: { 3000: identity(3000, "Grafana") },
      keys: ["y"],
      locale: "ko",
    });
    await selectLocalPort(t.context, 3000, PROJECT);
    expect(t.captured.stdout()).toContain(WARNING_KO);
  });

  it("warns for a clear framework mismatch", async () => {
    const t = setup({
      services: { 3000: identity(3000, "Hello", ["Werkzeug/3.0 Python/3.12"]) },
      keys: ["y"],
    });
    await selectLocalPort(t.context, 3000, { ...PROJECT, dependencies: ["django"] });
    expect(t.captured.stdout()).toContain("doesn't look related to this project");
  });

  it.each([
    ["a likely service", identity(3000, "Shop - Home")],
    ["an unclear service", identity(3000, "Landing page")],
  ])("shows no warning for %s", async (_label, service) => {
    const t = setup({ services: { 3000: service }, keys: ["y"] });
    await selectLocalPort(t.context, 3000, PROJECT);
    expect(t.captured.stdout()).not.toContain("doesn't look related");
    expect(t.captured.stdout()).not.toContain("관련 없어");
  });

  it("shows no warning when the project is unknown", async () => {
    const t = setup({ services: { 3000: identity(3000, "Grafana") }, keys: ["y"] });
    await selectLocalPort(t.context, 3000, null);
    expect(t.captured.stdout()).not.toContain("doesn't look related");
  });

  it("does not let the project's tool dependencies trigger the warning", async () => {
    const t = setup({ services: { 3000: identity(3000, "Grafana") }, keys: ["y"] });
    await selectLocalPort(t.context, 3000, { ...PROJECT, dependencies: ["@grafana/data"] });
    expect(t.captured.stdout()).not.toContain("doesn't look related");
  });

  it("strips escape sequences and caps what the service and the folder say", async () => {
    const hostile = `Grafana\u001b]0;pwned\u0007\u001b[31m‮${"z".repeat(300)}`;
    const t = setup({ services: { 3000: identity(3000, hostile) }, keys: ["y"] });
    await selectLocalPort(t.context, 3000, {
      ...PROJECT,
      folderName: `shop\u001b[2J‮${"q".repeat(300)}`,
    });
    const warning = t.captured
      .stdout()
      .split("\n")
      .find((line) => line.includes("look related"));
    expect(warning).toBeDefined();
    expect(warning).not.toMatch(/[\u001b\u0007‮]/);
    expect(warning?.length).toBeLessThan(200);
  });
});

describe("several servers", () => {
  const services = {
    3000: identity(3000, "Grafana"),
    4000: identity(4000, "Landing page"),
    5173: identity(5173, "Shop dev"),
  };

  it("offers the ones that look like this project first and marks them", async () => {
    const t = setup({ services, keys: [] });
    const targets = await findWebTargets(
      t.context,
      WEB_OFFER_BUDGET_MS,
      async () => true,
      async () => PROJECT,
    );
    expect(targets.map((target) => target.port)).toEqual([5173, 3000, 4000]);
    expect(targets[0]?.label).toContain("(name matches this project)");
    expect(targets[1]?.label).not.toContain("looks like this project");
  });

  it("marks in Korean", async () => {
    const t = setup({ services, keys: [], locale: "ko" });
    const targets = await findWebTargets(
      t.context,
      WEB_OFFER_BUDGET_MS,
      async () => true,
      async () => PROJECT,
    );
    expect(targets[0]?.label).toContain("(이름이 프로젝트와 비슷함)");
  });

  it("keeps the discovery order without project signals", async () => {
    const t = setup({ services, keys: [] });
    const targets = await findWebTargets(t.context);
    expect(targets.map((target) => target.port)).toEqual([3000, 4000, 5173]);
    expect(targets.every((target) => !target.label.includes("looks like"))).toBe(true);
  });

  it("keeps a likely server inside the list limit", async () => {
    const many: Record<number, ServiceIdentity> = {};
    for (let port = 3000; port < 3008; port += 1) many[port] = identity(port, "Landing page");
    many[3007] = identity(3007, "Shop dev");
    const t = setup({ services: many, keys: [] });
    const targets = await findWebTargets(
      t.context,
      WEB_OFFER_BUDGET_MS,
      async () => true,
      async () => PROJECT,
    );
    expect(targets[0]?.port).toBe(3007);
  });

  it("keeps one server the heuristic did not pick when every shown one matches", async () => {
    const many: Record<number, ServiceIdentity> = {};
    for (let port = 3000; port < 3008; port += 1) many[port] = identity(port, "Shop dev");
    many[3007] = identity(3007, "Landing page");
    const t = setup({ services: many, keys: [] });
    const targets = await findWebTargets(
      t.context,
      WEB_OFFER_BUDGET_MS,
      async () => true,
      async () => PROJECT,
    );
    expect(targets).toHaveLength(5);
    expect(targets[4]?.port).toBe(3007);
    expect(targets.slice(0, 4).every((target) => target.isLikely)).toBe(true);
  });

  it("does not wait for a project read that never finishes", async () => {
    const t = setup({ services, keys: [] });
    const started = Date.now();
    const targets = await findWebTargets(
      t.context,
      150,
      async () => true,
      () => new Promise<never>(() => undefined),
    );
    expect(Date.now() - started).toBeLessThan(1000);
    expect(targets.map((target) => target.port)).toEqual([3000, 4000, 5173]);
  });

  it("asks the confirmation in Korean", async () => {
    const t = setup({ services: { 3000: identity(3000, "Landing") }, keys: ["y"], locale: "ko" });
    await selectLocalPort(t.context, 3000, PROJECT);
    expect(t.captured.stdout()).toContain("이 프로젝트의 서비스가 맞습니까?");
  });

  it("orders the port list of the confirmation step the same way", async () => {
    const t = setup({ services, keys: ["escape"] });
    await selectLocalPort(t.context, null, PROJECT);
    const text = t.captured.stdout();
    expect(text.indexOf("127.0.0.1:5173")).toBeLessThan(text.indexOf("127.0.0.1:3000"));
    expect(text).toContain("(name matches this project)");
  });

  it("goes on without a judgement when reading the project fails", async () => {
    const t = setup({ services, keys: [] });
    const targets = await findWebTargets(
      t.context,
      WEB_OFFER_BUDGET_MS,
      async () => true,
      async () => {
        throw new Error("unreadable");
      },
    );
    expect(targets.map((target) => target.port)).toEqual([3000, 4000, 5173]);
  });
});
