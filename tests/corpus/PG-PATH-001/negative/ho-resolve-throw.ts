// corpus: expect=low
import { readFile } from "node:fs/promises";
import path from "node:path";
const ROOT = path.resolve(process.cwd(), "docs");

export async function doc(req: any) {
  const full = path.resolve(ROOT, String(req.query.page));
  if (!full.startsWith(ROOT + path.sep)) throw new Error("forbidden");
  return readFile(full, "utf8");
}
