// corpus: expect=none
const fs = require("node:fs");
const REPORTS = { daily: "reports/daily.csv", weekly: "reports/weekly.csv" };

module.exports = (req, res) => {
  const file = REPORTS[req.query.kind];
  if (!file) return res.sendStatus(404);
  fs.createReadStream(file).pipe(res);
};
