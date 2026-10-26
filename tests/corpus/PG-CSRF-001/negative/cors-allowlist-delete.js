// corpus: expect=none
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const app = express();
app.use(cookieParser());
app.use(cors({ origin: ["https://app.example.com"], credentials: true }));

app.delete("/account", (req, res) => {
  res.sendStatus(204);
});
