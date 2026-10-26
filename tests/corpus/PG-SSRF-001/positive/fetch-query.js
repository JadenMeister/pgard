// corpus: expect=PG-SSRF-001
app.get("/proxy", async (req, res) => {
  const upstream = await fetch(req.query.url);
  res.send(await upstream.text());
});
