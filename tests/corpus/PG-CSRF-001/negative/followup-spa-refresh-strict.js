// corpus: expect=none
// An SPA refresh_token cookie with SameSite=Strict is not sent on cross-site requests.
const express = require("express");
const app = express();
const SAME_SITE = "strict";

app.post("/start", (req, res) => {
  res.cookie("refresh_token", issue(req), { httpOnly: true, secure: true, sameSite: SAME_SITE });
  res.sendStatus(204);
});

app.post("/transfer", (req, res) => res.json({ ok: true }));
