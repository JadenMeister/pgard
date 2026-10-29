import { describe, expect, it, vi } from "vitest";
import {
  installDropGuard,
  readDroppedFolder,
  type DataTransferLike,
  type DropEntryLike,
  type DropItemLike,
} from "./drop";

/** A fake DataTransfer whose spies prove what the page may and may not touch (design test 17). */
function fakeTransfer(entries: Array<{ kind?: string; entry: DropEntryLike | null }>) {
  const getAsFile = vi.fn();
  const createReader = vi.fn();
  const items: DropItemLike[] = entries.map(({ kind, entry }) => ({
    kind: kind ?? "file",
    webkitGetAsEntry: () => (entry === null ? null : Object.assign({ createReader }, entry)),
    getAsFile,
  })) as DropItemLike[];
  const transfer: DataTransferLike = { items, types: ["Files"] };
  return { transfer, getAsFile, createReader };
}

describe("reading a dropped folder", () => {
  it("reads only the name and isDirectory, never the file, the directory reader or FileReader", () => {
    const reader = vi.fn();
    vi.stubGlobal("FileReader", reader);
    const { transfer, getAsFile, createReader } = fakeTransfer([
      { entry: { name: "shop", isDirectory: true } },
    ]);
    expect(readDroppedFolder(transfer)).toEqual({ kind: "folder", name: "shop" });
    expect(getAsFile).not.toHaveBeenCalled();
    expect(createReader).not.toHaveBeenCalled();
    expect(reader).not.toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("refuses a dropped file: the page shows 'Drop a folder, not a file'", () => {
    const { transfer, getAsFile } = fakeTransfer([
      { entry: { name: "notes.txt", isDirectory: false } },
    ]);
    expect(readDroppedFolder(transfer)).toEqual({ kind: "file" });
    expect(getAsFile).not.toHaveBeenCalled();
  });

  it("takes the first dropped item and ignores non-file items", () => {
    const { transfer } = fakeTransfer([
      { kind: "string", entry: { name: "text", isDirectory: true } },
      { entry: { name: "first", isDirectory: true } },
      { entry: { name: "second", isDirectory: true } },
    ]);
    expect(readDroppedFolder(transfer)).toEqual({ kind: "folder", name: "first" });
  });

  it("finds nothing usable when there are no items or no entry API", () => {
    expect(readDroppedFolder(null)).toEqual({ kind: "none" });
    expect(readDroppedFolder({ items: [] })).toEqual({ kind: "none" });
    expect(readDroppedFolder(fakeTransfer([{ entry: null }]).transfer)).toEqual({ kind: "none" });
    expect(readDroppedFolder({ items: [{ kind: "file" }] })).toEqual({ kind: "none" });
  });
});

describe("the page-wide drop guard (T6)", () => {
  function target() {
    return new EventTarget() as unknown as Pick<
      Window,
      "addEventListener" | "removeEventListener"
    > &
      EventTarget;
  }
  function fileDrag(type: string, types: string[] | null) {
    const event = new Event(type, { cancelable: true, bubbles: true });
    Object.defineProperty(event, "dataTransfer", { value: types === null ? null : { types } });
    return event;
  }

  it("cancels dragover and drop of files anywhere, so the browser never navigates to file://", () => {
    const window = target();
    installDropGuard(window);
    for (const type of ["dragover", "drop"]) {
      const event = fileDrag(type, ["Files"]);
      window.dispatchEvent(event);
      expect(event.defaultPrevented, type).toBe(true);
    }
  });

  it("also cancels a drag whose contents cannot be told (fail safe) but leaves text drags alone", () => {
    const window = target();
    installDropGuard(window);
    const unknown = fileDrag("drop", null);
    window.dispatchEvent(unknown);
    expect(unknown.defaultPrevented).toBe(true);
    const text = fileDrag("drop", ["text/plain"]);
    window.dispatchEvent(text);
    expect(text.defaultPrevented).toBe(false);
  });

  it("is removed by the returned function", () => {
    const window = target();
    const remove = installDropGuard(window);
    remove();
    const event = fileDrag("drop", ["Files"]);
    window.dispatchEvent(event);
    expect(event.defaultPrevented).toBe(false);
  });

  it("works for a document body listener chain too (events bubble to the window)", () => {
    const outer = new EventTarget();
    installDropGuard(outer as unknown as Window);
    const event = fileDrag("drop", ["Files"]);
    outer.dispatchEvent(event);
    expect(event.defaultPrevented).toBe(true);
  });
});
