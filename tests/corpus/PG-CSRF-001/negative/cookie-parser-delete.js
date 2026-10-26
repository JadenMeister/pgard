// corpus: expect=none
const express = require("express");
const cookieParser = require("cookie-parser");
const app = express();
app.use(cookieParser());

app.delete("/account", (req, res) => {
  res.sendStatus(204);
});
