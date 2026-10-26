// corpus: expect=PG-PATH-001
import { readFile } from "node:fs/promises";
import type { Context } from "koa";

export async function show(ctx: Context) {
  ctx.body = await readFile("./docs/" + ctx.params.page);
}
