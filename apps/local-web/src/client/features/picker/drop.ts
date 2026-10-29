/**
 * Reading a dropped folder, and keeping stray drops from navigating the page away (T6, T3).
 *
 * The page learns only the folder's _name_ and whether it is a directory. It never calls
 * `getAsFile`, never reads a directory's entries and never uses `FileReader`: a dropped folder's
 * contents never reach the page, let alone the server.
 */

/** What `webkitGetAsEntry()` returns that this page looks at. */
export interface DropEntryLike {
  name: string;
  isDirectory: boolean;
}

export interface DropItemLike {
  kind: string;
  webkitGetAsEntry?: () => DropEntryLike | null;
}

export interface DataTransferLike {
  items?: ArrayLike<DropItemLike> | null;
  types?: ArrayLike<string> | null;
}

export type DroppedFolder = { kind: "folder"; name: string } | { kind: "file" } | { kind: "none" };

/** The first dropped item: a folder (its name), a file (refused) or nothing usable. */
export function readDroppedFolder(
  dataTransfer: DataTransferLike | null | undefined,
): DroppedFolder {
  const items = dataTransfer?.items;
  if (items === null || items === undefined) return { kind: "none" };
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    if (item === undefined || item.kind !== "file") continue;
    const entry = item.webkitGetAsEntry?.() ?? null;
    if (entry === null) return { kind: "none" };
    return entry.isDirectory ? { kind: "folder", name: entry.name } : { kind: "file" };
  }
  return { kind: "none" };
}

function carriesFiles(dataTransfer: DataTransferLike | null | undefined): boolean {
  const types = dataTransfer?.types;
  if (types === null || types === undefined) return true; // unknown: treat as files (fail safe)
  for (let index = 0; index < types.length; index += 1) {
    if (types[index] === "Files") return true;
  }
  return false;
}

/**
 * A drop that misses the drop zone would make the browser navigate to the dropped `file://` URL,
 * which shows the path in the address bar and the history and throws away the in-memory session.
 * These listeners cancel every file drag over the whole page. A drag of text (into the search
 * box) is left alone. Returns the function that removes them.
 */
export function installDropGuard(target: Pick<Window, "addEventListener" | "removeEventListener">) {
  const guard = (event: Event): void => {
    const { dataTransfer } = event as DragEvent;
    if (carriesFiles(dataTransfer)) event.preventDefault();
  };
  target.addEventListener("dragover", guard);
  target.addEventListener("drop", guard);
  return () => {
    target.removeEventListener("dragover", guard);
    target.removeEventListener("drop", guard);
  };
}
