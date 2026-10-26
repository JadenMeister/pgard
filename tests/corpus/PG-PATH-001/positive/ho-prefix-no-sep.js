// corpus: expect=PG-PATH-001
// A prefix check whose suffix is not a separator lets /srv/public-secrets pass for /srv/public.
const path = require("node:path");
const ROOT = path.resolve("/srv/public");

module.exports = (req, res) => {
  const full = path.resolve(ROOT, req.query.f);
  if (!full.startsWith(ROOT + "x")) return res.sendStatus(403);
  res.sendFile(full);
};
