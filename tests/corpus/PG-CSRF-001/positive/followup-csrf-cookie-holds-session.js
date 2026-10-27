// corpus: expect=PG-CSRF-001,PG-COOKIE-001
const express = require("express");
const app = express();
app.post("/start", async (req, res) => {
  res.cookie("csrf_token", req.sessionID, {});
  res.end();
});
app.post("/transfer", (req, res) => res.end());
