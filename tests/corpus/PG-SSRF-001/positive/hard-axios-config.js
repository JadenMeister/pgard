// corpus: expect=PG-SSRF-001
const axios = require("axios");

module.exports = async (req, res) => {
  const upstream = await axios({ method: "get", url: req.query.url });
  res.send(upstream.data);
};
