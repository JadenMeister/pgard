// corpus: expect=PG-CSRF-001,PG-COOKIE-001
// A hand-rolled session cookie, with no session library.
const express = require("express");
const app = express();

app.post("/start", (req, res) => {
  res.cookie("session", issue(req));
  res.sendStatus(204);
});

app.post("/transfer", (req, res) => {
  const user = lookup(req.headers.cookie);
  res.json({ from: user.id });
});
