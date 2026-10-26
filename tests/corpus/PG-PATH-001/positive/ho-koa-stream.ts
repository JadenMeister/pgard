// corpus: expect=PG-PATH-001
import { createReadStream } from "node:fs";

export function download(ctx: any) {
  ctx.body = createReadStream(ctx.query.f);
}
