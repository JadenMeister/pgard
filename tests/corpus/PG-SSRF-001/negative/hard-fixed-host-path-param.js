// corpus: expect=none; known=fp:PG-SSRF-001:a request value placed in the path of a fixed https host is reported as if it chose the host
app.get("/users/:id", async (req, res) => {
  const id = encodeURIComponent(req.params.id);
  const upstream = await fetch("https://api.example.com/users/" + id);
  res.json(await upstream.json());
});
