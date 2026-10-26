// corpus: expect=PG-PATH-001
// startsWith(ROOT) without a separator lets /srv/public-secrets pass for /srv/public.
const path = require("node:path");
const ROOT = path.resolve("/srv/public");

module.exports = (req, res) => {
  const full = path.resolve(ROOT, req.query.f);
  if (!full.startsWith(ROOT)) return res.sendStatus(403);
  res.sendFile(full);
};
