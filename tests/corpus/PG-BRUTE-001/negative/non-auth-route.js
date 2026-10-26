// corpus: expect=none
const express = require("express");
const app = express();

app.post("/comments", (req, res) => res.sendStatus(201));
