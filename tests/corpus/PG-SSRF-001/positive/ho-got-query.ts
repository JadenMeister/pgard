// corpus: expect=PG-SSRF-001
import got from "got";

export async function preview(ctx: any) {
  const { url } = ctx.query;
  ctx.body = await got(url).text();
}
