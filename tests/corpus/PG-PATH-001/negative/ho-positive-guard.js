// corpus: expect=low
const fs = require("fs");
const path = require("path");
const { sep } = path;
const BASE = fs.realpathSync("assets");

module.exports = (req, res) => {
  const full = fs.realpathSync(path.join(BASE, req.params.name));
  if (full.startsWith(BASE + sep)) {
    return res.sendFile(full);
  }
  res.sendStatus(404);
};
