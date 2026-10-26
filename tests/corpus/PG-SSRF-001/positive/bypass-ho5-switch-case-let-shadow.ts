// corpus: expect=PG-SSRF-001
export async function pull(req: any, res: any) {
  const u = new URL(req.query.url);
  if (u.hostname !== "api.example.com" || u.protocol !== "https:") return res.sendStatus(400);
  switch (req.query.mode) {
    case "mirror":
      let u = new URL(req.query.mirror);
      return res.send(await (await fetch(u)).text());
    default:
      return res.send("ok");
  }
}
