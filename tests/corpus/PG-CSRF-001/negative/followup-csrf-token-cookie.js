// corpus: expect=none
// A csrf_token cookie is readable by design and is not a session.
const express = require("express");
const app = express();

app.get("/form", (req, res) => {
  res.cookie("csrf_token", makeToken(), { path: "/", secure: true, sameSite: "lax" });
  res.sendStatus(204);
});

app.post("/save", (req, res) => res.json({ ok: true }));
