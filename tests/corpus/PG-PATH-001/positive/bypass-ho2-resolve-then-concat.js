// corpus: expect=PG-PATH-001
const fs = require("fs");
const path = require("path");
const ROOT = path.resolve("public");
module.exports = (req, res) => {
  const full = path.resolve("public") + "/" + req.query.file;
  if (!full.startsWith(ROOT + path.sep)) return res.sendStatus(403);
  fs.createReadStream(full).pipe(res);
};
