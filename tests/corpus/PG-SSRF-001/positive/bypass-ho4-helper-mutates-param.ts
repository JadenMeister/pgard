// corpus: expect=PG-SSRF-001
function retarget(url: URL, host: string) {
  url.host = host;
}
export async function relay(req: any, res: any) {
  const dest = new URL(req.query.dest);
  if (dest.hostname !== "hooks.example.com" || dest.protocol !== "https:") return res.sendStatus(403);
  retarget(dest, req.query.region);
  res.json(await (await fetch(dest)).json());
}
