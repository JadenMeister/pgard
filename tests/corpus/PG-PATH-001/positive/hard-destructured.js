// corpus: expect=PG-PATH-001
const fs = require("node:fs");

module.exports = (req, res) => {
  const { file } = req.query;
  fs.readFile("./public/" + file, (err, data) => res.send(data));
};
