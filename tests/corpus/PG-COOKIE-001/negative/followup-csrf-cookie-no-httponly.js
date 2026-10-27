// corpus: expect=none
// csrf/xsrf cookies must be readable by scripts, so no httpOnly is expected.
app.get("/", (req, res) => {
  res.cookie("csrf_token", makeToken(), { secure: true, sameSite: "lax" });
  res.cookie("XSRF-TOKEN", makeToken(), { secure: true, sameSite: "lax" });
  res.sendStatus(204);
});
