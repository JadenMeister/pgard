// corpus: expect=PG-COOKIE-001
app.get("/cb", (req, res) => {
  res.cookie("app", accessToken);
  res.sendStatus(204);
});
