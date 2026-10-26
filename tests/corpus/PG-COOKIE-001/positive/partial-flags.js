// corpus: expect=PG-COOKIE-001
app.get("/oauth/callback", (req, res) => {
  res.cookie("session", issueToken(req.query.code), { httpOnly: true });
  res.sendStatus(204);
});
