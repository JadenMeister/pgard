// corpus: expect=none
const express = require("express");
const app = express();
const STRICT = { sameSite: "strict" };
const BASE = { httpOnly: true, secure: true, ...STRICT };
app.post("/start", async (req, res) => {
  res.cookie("sid", await login(req.body), { ...BASE });
  res.end();
});
app.post("/transfer", (req, res) => res.end());
