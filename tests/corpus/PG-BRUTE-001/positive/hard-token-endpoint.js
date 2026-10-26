// corpus: expect=PG-BRUTE-001
const express = require("express");
const app = express();

app.post("/oauth/token", async (req, res) => {
  res.json(await exchange(req.body.username, req.body.password));
});
