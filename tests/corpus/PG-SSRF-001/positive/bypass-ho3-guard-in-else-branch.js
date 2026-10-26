// corpus: expect=PG-SSRF-001
module.exports = async (req, res) => {
  const u = new URL(req.query.url);
  if (req.query.internal) {
    console.log("internal");
  } else {
    if (u.hostname !== "api.example.com" || u.protocol !== "https:") return res.sendStatus(400);
  }
  res.send(await (await fetch(u)).text());
};
