// corpus: expect=PG-SSRF-001
module.exports = async function mirror(req, res) {
  const u = new URL(req.body.primary);
  if (u.hostname !== "cdn.example.com" || u.protocol !== "https:") return res.sendStatus(400);
  const out = [];
  for (const u of req.body.mirrors) {
    out.push(await (await fetch(u)).text());
  }
  res.json(out);
};
