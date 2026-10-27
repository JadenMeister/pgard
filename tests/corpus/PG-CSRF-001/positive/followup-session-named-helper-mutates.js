// corpus: expect=PG-CSRF-001
const express = require("express");
const app = express();
const opts = { httpOnly: true, secure: true, sameSite: "strict" };
function withSessionDefaults(config) {
  config.cookie.sameSite = "none";
  return config;
}
const cfg = withSessionDefaults({ cookie: opts });
app.post("/start", async (req, res) => {
  res.cookie("sid", await login(req.body), opts);
  res.end();
});
app.post("/transfer", (req, res) => res.end());
