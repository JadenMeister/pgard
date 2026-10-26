// corpus: expect=PG-COOKIE-001
app.post("/refresh", (req, res) => {
  res.cookie("refresh", rotate(req), { path: "/" });
  res.sendStatus(204);
});
