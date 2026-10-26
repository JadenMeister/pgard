// corpus: expect=PG-SSRF-001
import got from "got";

export async function relay(req: { query: { u: string } }) {
  return got(req.query.u).text();
}
