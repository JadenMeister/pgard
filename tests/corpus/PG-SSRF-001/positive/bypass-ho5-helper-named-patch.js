// corpus: expect=PG-SSRF-001
function patch(url, overrides) {
  Object.assign(url, overrides);
  return url;
}
module.exports = async (req, res) => {
  const u = new URL(req.query.url);
  if (u.hostname !== "api.example.com" || u.protocol !== "https:") return res.sendStatus(400);
  patch(u, { hostname: req.query.host });
  res.send(await (await fetch(u)).text());
};
