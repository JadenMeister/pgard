// corpus: expect=PG-SSRF-001
module.exports = async (req, res) => {
  const u = new URL(req.query.url);
  if (u.hostname !== "api.example.com" || u.protocol !== "https:") return res.sendStatus(400);
  Object.assign(u, { hostname: req.query.host });
  u.hostname = req.query.host;
  res.send(await (await fetch(u)).text());
};
