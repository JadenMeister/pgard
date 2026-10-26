// corpus: expect=none
const fs = require("node:fs");
const path = require("node:path");

module.exports = (req, res) => {
  const name = path.basename(req.params.name);
  res.send(fs.readFileSync(path.join("static", name)));
};
