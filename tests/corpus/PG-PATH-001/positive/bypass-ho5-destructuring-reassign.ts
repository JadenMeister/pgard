// corpus: expect=PG-PATH-001
import fs from "node:fs";
import path from "node:path";
const ROOT = path.resolve("files");
export function read(req: any, res: any) {
  let full = path.resolve(ROOT, req.query.f);
  if (!full.startsWith(ROOT + path.sep)) return res.sendStatus(403);
  ({ full } = { full: req.query.raw });
  res.send(fs.readFileSync(full));
}
