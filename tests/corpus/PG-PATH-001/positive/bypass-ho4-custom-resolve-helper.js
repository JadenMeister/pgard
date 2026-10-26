// corpus: expect=PG-PATH-001
const fs = require("fs");
const path = require("path");
const ROOT = "/srv/files";
const resolve = (base, name) => `${base}/${name}`;
module.exports = (req, res) => {
  const full = resolve(ROOT, req.query.name);
  if (!full.startsWith(ROOT + path.sep)) return res.sendStatus(403);
  res.send(fs.readFileSync(full));
};
