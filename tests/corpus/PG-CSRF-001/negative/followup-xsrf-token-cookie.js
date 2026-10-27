// corpus: expect=none
// The Angular-style XSRF-TOKEN cookie is readable by design and is not a session.
const express = require("express");
const app = express();

app.get("/", (req, res) => {
  res.cookie("XSRF-TOKEN", makeToken(), { secure: true, sameSite: "lax" });
  res.sendStatus(204);
});

app.post("/save", (req, res) => res.json({ ok: true }));
