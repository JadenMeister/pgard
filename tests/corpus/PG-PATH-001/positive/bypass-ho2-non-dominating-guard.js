// corpus: expect=PG-PATH-001
const fs = require("fs");
const path = require("path");
const ROOT = path.resolve("docs");
module.exports = (req, res) => {
  const full = path.resolve(ROOT, req.query.doc);
  if (req.query.strict) {
    if (!full.startsWith(ROOT + path.sep)) return res.sendStatus(403);
  }
  res.send(fs.readFileSync(full, "utf8"));
};
