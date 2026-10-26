// corpus: expect=none; allow=low
export async function avatar(req: any, res: any) {
  const u = new URL(String(req.query.src));
  if (u.hostname !== "avatars.example.com" || u.protocol !== "https:") {
    return res.sendStatus(400);
  }
  res.send(Buffer.from(await (await fetch(u.href)).arrayBuffer()));
}
