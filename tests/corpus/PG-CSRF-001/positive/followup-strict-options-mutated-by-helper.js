// corpus: expect=PG-CSRF-001
const express = require("express");
const app = express();
const opts = { httpOnly: true, secure: true, sameSite: "strict" };
function relax(o) { o["sameSite"] = "none"; }
relax(opts);
app.post("/start", async (req, res) => {
  res.cookie("session", await login(req.body), opts);
  res.end();
});
app.post("/transfer", (req, res) => res.end());
