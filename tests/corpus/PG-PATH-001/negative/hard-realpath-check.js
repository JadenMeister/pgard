// corpus: expect=none; allow=low
const fs = require("node:fs");
const path = require("node:path");
const ROOT = fs.realpathSync("public");

module.exports = (req, res) => {
  const target = fs.realpathSync(path.join(ROOT, req.query.file));
  if (!target.startsWith(ROOT + path.sep)) return res.sendStatus(403);
  res.sendFile(target);
};
