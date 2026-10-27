// corpus: expect=PG-CSRF-001
const express = require("express");
const app = express();
const MODE = "strict";
function setSession(res, id, MODE) {
  res.cookie("session", id, { httpOnly: true, secure: true, sameSite: MODE });
}
app.post("/start", async (req, res) => {
  setSession(res, await login(req.body), req.query.embed ? "none" : "lax");
  res.end();
});
app.post("/transfer", (req, res) => res.end());
