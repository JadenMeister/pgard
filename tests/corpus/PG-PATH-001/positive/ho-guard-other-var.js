// corpus: expect=PG-PATH-001
// The guard checks a different value than the one that is opened.
const fs = require("node:fs");
const path = require("node:path");
const ROOT = path.resolve("data");

module.exports = (req, res) => {
  const safe = path.resolve(ROOT, "index.html");
  const requested = path.resolve(ROOT, req.query.file);
  if (!safe.startsWith(ROOT + path.sep)) return res.sendStatus(403);
  res.send(fs.readFileSync(requested));
};
