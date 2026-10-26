// corpus: expect=none
app.get("/oauth/callback", (req, res) => {
  res.cookie("sid", issueToken(req.query.code), { httpOnly: true, secure: true, sameSite: "lax" });
  res.sendStatus(204);
});
