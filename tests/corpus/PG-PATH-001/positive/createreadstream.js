// corpus: expect=PG-PATH-001
const fs = require("node:fs");

module.exports = (req, res) => {
  fs.createReadStream(`/srv/files/${req.params.file}`).pipe(res);
};
