// corpus: expect=PG-SSRF-001
module.exports = async (req, res) => {
  let u = new URL(req.query.url);
  if (u.hostname !== "api.example.com" || u.protocol !== "https:") return res.sendStatus(400);
  u = new URL(req.query.redirect);
  res.send(await (await fetch(u)).text());
};
