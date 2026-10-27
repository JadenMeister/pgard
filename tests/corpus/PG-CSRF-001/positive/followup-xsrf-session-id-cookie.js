// corpus: expect=PG-CSRF-001,PG-COOKIE-001
// A session cookie that merely mentions xsrf is still a session cookie.
const express = require("express");
const app = express();

app.post("/start", (req, res) => {
  res.cookie("xsrf_session_id", issue(req), { path: "/" });
  res.sendStatus(204);
});

app.post("/transfer", (req, res) => res.json({ ok: true }));
