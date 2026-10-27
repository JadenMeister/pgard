// corpus: expect=none
// A weak-named cookie (user_prefs) is not evidence of a cookie session.
const express = require("express");
const app = express();

app.get("/prefs", (req, res) => {
  res.cookie("user_prefs", "dark", { httpOnly: true, secure: true, sameSite: "lax" });
  res.sendStatus(204);
});

app.post("/prefs", (req, res) => res.json({ ok: true }));
