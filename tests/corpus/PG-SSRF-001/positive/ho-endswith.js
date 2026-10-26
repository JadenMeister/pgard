// corpus: expect=PG-SSRF-001
// A suffix check accepts evilexample.com.
app.get("/fetch", async (req, res) => {
  const u = new URL(req.query.url);
  if (!u.hostname.endsWith("example.com") || u.protocol !== "https:") return res.sendStatus(400);
  res.send(await (await fetch(u)).text());
});
