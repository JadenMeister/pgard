// corpus: expect=PG-SSRF-001
const axios = require("axios");

module.exports = async (req, res) => {
  const reply = await axios.post(req.body.webhook, { ok: true });
  res.json(reply.data);
};
