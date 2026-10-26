// corpus: expect=PG-PATH-001
const fs = require("fs");
const path = require("path");
const ROOT = path.resolve("files");
module.exports = (req, res) => {
  let full = path.resolve(ROOT, req.query.f);
  if (!full.startsWith(ROOT + path.sep)) return res.sendStatus(403);
  const out = [];
  for (full of [].concat(req.query.more || [])) out.push(fs.readFileSync(full, "utf8"));
  res.json(out);
};
