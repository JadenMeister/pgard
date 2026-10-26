// corpus: expect=PG-SSRF-001
export async function proxy(req: any, res: any) {
  const u = new URL(req.query.target);
  if (u.protocol !== "https:") return res.sendStatus(400);
  const upstream = await fetch(u);
  res.send(await upstream.text());
}
