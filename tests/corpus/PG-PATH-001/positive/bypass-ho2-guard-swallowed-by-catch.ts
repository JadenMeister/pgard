// corpus: expect=PG-PATH-001
import fs from "node:fs";
import path from "node:path";
const ROOT = path.resolve("data");
export function read(req: any, res: any) {
  const full = path.resolve(ROOT, req.params.name);
  try {
    if (!full.startsWith(ROOT + path.sep)) throw new Error("outside");
  } catch (err) {
    console.warn(err);
  }
  res.send(fs.readFileSync(full));
}
