// corpus: expect=PG-CRYPTO-002
const express = require("express");
const jwt = require("jsonwebtoken");

const SECRET = "keyboard cat";
const app = express();

app.get("/refresh", (req, res) => {
  const token = jwt.sign({ id: req.body.id }, SECRET, { expiresIn: "1d" });
  res.json({ token });
});
