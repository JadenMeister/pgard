import type { AddressWindow } from "./use-filter-state";

/**
 * A browser address bar for tests: `location.hash`, `history.pushState/replaceState/back/forward`
 * and the `hashchange` and `popstate` events, with the same rules as a browser (setting the hash
 * fires `hashchange` and adds an entry; `pushState` and `replaceState` fire nothing; going back
 * fires `popstate` and, when the fragment differs, `hashchange`).
 */
export class FakeWindow implements AddressWindow {
  pathname = "/";
  search = "";
  readonly entries: string[];
  index = 0;
  /** Every pushState and replaceState call, in order. */
  readonly calls: Array<{ kind: "push" | "replace"; url: string }> = [];
  private readonly listeners = new Map<string, Set<() => void>>();

  constructor(initialHash = "") {
    this.entries = [initialHash];
  }

  get location() {
    const self = this;
    return {
      get hash(): string {
        return self.entries[self.index] ?? "";
      },
      set hash(value: string) {
        const next = value === "" ? "" : `#${value.replace(/^#/, "")}`;
        if (next === self.entries[self.index]) return;
        self.entries.splice(self.index + 1, Infinity, next);
        self.index += 1;
        self.emit("hashchange");
      },
      get pathname(): string {
        return self.pathname;
      },
      get search(): string {
        return self.search;
      },
    };
  }

  get history() {
    const hashOf = (url: string): string =>
      url.slice(url.indexOf("#") === -1 ? url.length : url.indexOf("#"));
    return {
      pushState: (_state: unknown, _title: string, url: string): void => {
        this.calls.push({ kind: "push", url });
        this.entries.splice(this.index + 1, Infinity, hashOf(url));
        this.index += 1;
      },
      replaceState: (_state: unknown, _title: string, url: string): void => {
        this.calls.push({ kind: "replace", url });
        this.entries[this.index] = hashOf(url);
      },
    };
  }

  back(): void {
    this.go(-1);
  }

  forward(): void {
    this.go(1);
  }

  private go(delta: number): void {
    const target = this.index + delta;
    if (target < 0 || target >= this.entries.length) return;
    const before = this.entries[this.index];
    this.index = target;
    this.emit("popstate");
    if (this.entries[this.index] !== before) this.emit("hashchange");
  }

  private emit(type: string): void {
    for (const listener of [...(this.listeners.get(type) ?? [])]) listener();
  }

  addEventListener(type: "hashchange" | "popstate", listener: () => void): void {
    const set = this.listeners.get(type) ?? new Set();
    set.add(listener);
    this.listeners.set(type, set);
  }

  removeEventListener(type: "hashchange" | "popstate", listener: () => void): void {
    this.listeners.get(type)?.delete(listener);
  }

  listenerCount(): number {
    return [...this.listeners.values()].reduce((sum, set) => sum + set.size, 0);
  }
}
