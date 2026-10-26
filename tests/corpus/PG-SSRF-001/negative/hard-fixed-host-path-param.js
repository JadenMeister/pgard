// corpus: expect=none; known=fp:PG-SSRF-001:path only, host fixed, and `..` can reach other paths on the same host
app.get("/users/:id", async (req, res) => {
  const id = encodeURIComponent(req.params.id);
  const upstream = await fetch("https://api.example.com/users/" + id);
  res.json(await upstream.json());
});
