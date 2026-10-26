// corpus: expect=PG-COOKIE-001
app.get("/oauth/callback", (req, res) => {
  const token = issueToken(req.query.code);
  res.cookie("sid", token);
  res.sendStatus(204);
});
