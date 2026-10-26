// corpus: expect=PG-SSRF-001
export async function both(req: any, res: any) {
  const u = new URL(req.query.a);
  if (u.hostname !== "api.example.com" || u.protocol !== "https:") return res.sendStatus(400);
  {
    const u = new URL(req.query.b);
    res.send(await (await fetch(u)).text());
  }
}
