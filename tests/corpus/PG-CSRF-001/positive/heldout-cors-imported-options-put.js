// corpus: expect=PG-CSRF-001
// The CORS options live in another module, so the preflight cannot be assumed to block a cross-site PUT.
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const corsOptions = require("./cors-options");
const app = express();
app.use(cookieParser());
app.use(cors(corsOptions));

app.put("/profile", (req, res) => {
  res.sendStatus(204);
});
