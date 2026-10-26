// corpus: expect=none
const ALLOWED_HOSTS = new Set(["api.example.com", "files.example.com"]);

module.exports = async (req, res) => {
  const target = new URL(req.body.url);
  const host = target.hostname;
  if (!["http:", "https:"].includes(target.protocol) || !ALLOWED_HOSTS.has(host)) {
    return res.status(400).end();
  }
  const upstream = await fetch(target);
  res.json(await upstream.json());
};
