// corpus: expect=PG-PATH-001
const fs = require("node:fs");
const path = require("node:path");
const BASE = path.join(__dirname, "uploads");

module.exports = (req, res) => {
  res.send(fs.readFileSync(path.join(BASE, req.query.name), "utf8"));
};
