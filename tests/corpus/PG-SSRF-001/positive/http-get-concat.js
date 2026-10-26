// corpus: expect=PG-SSRF-001
const https = require("node:https");

module.exports = (req, res) => {
  https.get("https://" + req.query.host + "/status", (upstream) => upstream.pipe(res));
};
