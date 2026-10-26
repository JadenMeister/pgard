// corpus: expect=PG-SSRF-001
module.exports = async (req, res) => {
  const u = new URL(req.query.url);
  for (const _ of [].concat(req.query.checks || [])) {
    if (u.hostname !== "api.example.com" || u.protocol !== "https:") return res.sendStatus(400);
  }
  res.send(await (await fetch(u)).text());
};
