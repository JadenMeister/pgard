// corpus: expect=low
app.get("/users/:id", async (req, res) => {
  const id = encodeURIComponent(req.params.id);
  const upstream = await fetch("https://api.example.com/users/" + id);
  res.json(await upstream.json());
});
