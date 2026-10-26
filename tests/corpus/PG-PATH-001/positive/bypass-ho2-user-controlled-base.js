// corpus: expect=PG-PATH-001
const fs = require("fs");
const path = require("path");
module.exports = (req, res) => {
  const full = path.resolve(req.query.base, req.query.file);
  if (!full.startsWith(req.query.base + path.sep)) return res.sendStatus(403);
  res.send(fs.readFileSync(full));
};
