// corpus: expect=PG-CSRF-001
const express = require("express");
const app = express();
const sameSite = "strict";
app.post("/start", async (req, res) => {
  const { sameSite } = await loadCookiePolicy(req.hostname);
  res.cookie("sid", await login(req.body), { httpOnly: true, secure: true, sameSite });
  res.end();
});
app.post("/transfer", (req, res) => res.end());
