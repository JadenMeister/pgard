import { describe, expect, it } from "vitest";
import { hasInviteToken, hasSessionToken } from "../api/client";
import { EMPTY_FILTERS, toggleFilter } from "../features/findings/filter-findings";
import { FakeWindow } from "./fake-window";
import { prepareAddress } from "./startup";
import { createFilterStore } from "./use-filter-state";
import { hashForView, viewFromHash } from "./views";

const TOKEN = "abcdefghijklmnopqrstuvwxyz012345";

describe("filter store (the address is the state)", () => {
  it("pushes a history entry for a click and replaces it while typing", () => {
    const win = new FakeWindow("#overview");
    const store = createFilterStore(win);
    store.set({ severity: "high" });
    store.set({ category: "xss" });
    store.set({ text: "s" }, { replace: true });
    store.set({ text: "sq" }, { replace: true });
    expect(win.calls.map((call) => call.kind)).toEqual(["push", "push", "push", "replace"]);
    expect(win.location.hash).toBe("#overview?severity=high&category=xss&q=sq");
    // Back undoes the first typed character's entry, not one entry per keystroke.
    expect(win.entries).toEqual([
      "#overview",
      "#overview?severity=high",
      "#overview?severity=high&category=xss",
      "#overview?severity=high&category=xss&q=sq",
    ]);
    expect(store.getSnapshot()).toMatchObject({ severity: "high", category: "xss", text: "sq" });
  });

  it("does not add an entry when nothing changes, and keeps the snapshot stable", () => {
    const win = new FakeWindow("#findings?severity=high");
    const store = createFilterStore(win);
    const first = store.getSnapshot();
    store.set({ severity: "high" });
    expect(win.calls).toEqual([]);
    expect(store.getSnapshot()).toBe(first);
  });

  it("follows popstate and hashchange, and notifies subscribers", () => {
    const win = new FakeWindow("#overview");
    const store = createFilterStore(win);
    let notified = 0;
    const unsubscribe = store.subscribe(() => (notified += 1));
    store.set({ severity: "critical" });
    expect(notified).toBe(1);
    win.back();
    expect(notified).toBeGreaterThan(1);
    expect(store.getSnapshot().severity).toBeNull();
    win.forward();
    expect(store.getSnapshot().severity).toBe("critical");
    // A view change made by setting the hash keeps the filters (see hashForView) and notifies.
    const before = notified;
    win.location.hash = "#coverage?severity=critical&rule=PG-SQL-001";
    expect(notified).toBeGreaterThan(before);
    expect(store.getSnapshot()).toMatchObject({ severity: "critical", rule: "PG-SQL-001" });
    unsubscribe();
    expect(win.listenerCount()).toBe(0);
  });

  it("keeps the view when a filter changes and clears everything with clear()", () => {
    const win = new FakeWindow("#findings");
    const store = createFilterStore(win);
    store.set({ rule: "PG-SQL-001", path: "src/a.ts" });
    expect(viewFromHash(win.location.hash)).toBe("findings");
    store.clear();
    expect(win.location.hash).toBe("#findings");
    expect(store.getSnapshot()).toEqual(EMPTY_FILTERS);
  });

  it("applies two changes made in one event", () => {
    const win = new FakeWindow("#overview");
    const store = createFilterStore(win);
    store.set({ severity: "low" });
    store.set({ category: "xss" });
    expect(store.getSnapshot()).toMatchObject({ severity: "low", category: "xss" });
  });

  it("reproduces a click: toggling a value on and off", () => {
    const win = new FakeWindow("#overview");
    const store = createFilterStore(win);
    const click = (patch: Parameters<typeof toggleFilter>[1]): void =>
      store.set(toggleFilter(store.getSnapshot(), patch));
    click({ category: "xss" });
    expect(win.location.hash).toBe("#overview?category=xss");
    click({ rule: "PG-XSS-001" });
    expect(win.location.hash).toBe("#overview?category=xss&rule=PG-XSS-001");
    click({ category: "xss" });
    expect(win.location.hash).toBe("#overview?rule=PG-XSS-001");
    win.back();
    expect(store.getSnapshot()).toMatchObject({ category: "xss", rule: "PG-XSS-001" });
  });
});

describe("view navigation carries the filters", () => {
  it("keeps the query when the view changes", () => {
    expect(hashForView("#overview?severity=high&category=xss", "findings")).toBe(
      "findings?severity=high&category=xss",
    );
    expect(hashForView("#overview", "coverage")).toBe("coverage");
    expect(hashForView("", "findings")).toBe("findings");
  });

  it("does nothing when the address already shows the view", () => {
    expect(hashForView("#findings?severity=high", "findings")).toBeNull();
    expect(hashForView("#findings", "findings")).toBeNull();
  });

  it("opens the overview from an empty address", () => {
    expect(hashForView("", "overview")).toBe("overview");
  });
});

describe("startup: the token leaves the address, the view and filters stay", () => {
  function startup(hash: string): FakeWindow {
    const win = new FakeWindow(hash);
    prepareAddress({
      location: win.location as unknown as Location,
      history: win.history as unknown as History,
    });
    return win;
  }

  it("removes the token, then restores only the allow-listed view and filters", () => {
    const win = startup(`#findings?severity=high&category=xss&token=${TOKEN}`);
    // Only held for the exchange: no session until the server trades it.
    expect(hasInviteToken()).toBe(true);
    expect(hasSessionToken()).toBe(false);
    expect(win.location.hash).toBe("#findings?severity=high&category=xss");
    // First the whole fragment is cleared (no entry ever holds the token afterwards), then restored.
    expect(win.calls.map((call) => call.url)).toEqual([
      "/",
      "/#findings?severity=high&category=xss",
    ]);
    expect(win.entries.join("|")).not.toContain(TOKEN);
  });

  it("leaves a bare address after a token-only fragment", () => {
    const win = startup(`#token=${TOKEN}`);
    expect(win.location.hash).toBe("");
    expect(win.calls.map((call) => call.url)).toEqual(["/"]);
  });

  it("never copies unknown fragment content back", () => {
    const win = startup(`#overview?severity=high&secret=${TOKEN}&token=${TOKEN}`);
    expect(win.location.hash).toBe("#overview?severity=high");
    expect(win.entries.join("|")).not.toContain(TOKEN);
  });
});
