// corpus: expect=PG-SSRF-001
module.exports = async function (req, res) {
  var u = new URL(req.query.url);
  if (u.hostname !== "api.example.com" || u.protocol !== "https:") return res.sendStatus(400);
  if (req.query.alt) {
    var u = new URL(req.query.alt);
  }
  res.send(await (await fetch(u)).text());
};
