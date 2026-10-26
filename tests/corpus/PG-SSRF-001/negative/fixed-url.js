// corpus: expect=none
app.get("/rates", async (req, res) => {
  const upstream = await fetch("https://api.example.com/rates");
  res.json(await upstream.json());
});
