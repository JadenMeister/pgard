// corpus: expect=PG-CSRF-001
const express = require("express");
const app = express();
const opts = { httpOnly: true, secure: true, sameSite: "strict" };
if (process.env.EMBED) opts.sameSite = "none";
app.post("/start", async (req, res) => {
  res.cookie("sid", await login(req.body), opts);
  res.end();
});
app.post("/transfer", (req, res) => res.end());
