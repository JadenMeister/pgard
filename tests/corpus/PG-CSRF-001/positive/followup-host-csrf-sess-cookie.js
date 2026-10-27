// corpus: expect=PG-CSRF-001,PG-COOKIE-001
const express = require("express");
const app = express();

app.post("/start", (req, res) => {
  res.cookie("__Host-csrf-sess", issue(req), { path: "/" });
  res.sendStatus(204);
});

app.post("/transfer", (req, res) => res.json({ ok: true }));
