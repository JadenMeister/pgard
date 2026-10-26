// corpus: expect=PG-SSRF-001
function applyAlias(r) {
  if (r.query.alias) r.query.url = r.query.alias;
}
module.exports = async (req, res) => {
  const u = new URL(req.query.url);
  if (u.hostname !== "api.example.com" || u.protocol !== "https:") return res.sendStatus(400);
  applyAlias(req);
  res.send(await (await fetch(req.query.url)).text());
};
