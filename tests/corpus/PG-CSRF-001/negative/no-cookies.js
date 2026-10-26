// corpus: expect=none
const express = require("express");
const app = express();
app.use(express.json());

// Bearer-token API: no cookie session.
app.post("/items", (req, res) => res.status(201).json(req.body));
