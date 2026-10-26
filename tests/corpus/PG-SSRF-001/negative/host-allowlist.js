// corpus: expect=none; known=fp:PG-SSRF-001:a URL checked against a hostname allowlist before fetch is still reported
const ALLOWED = new Set(["images.example.com", "cdn.example.com"]);

app.get("/img", async (req, res) => {
  const u = new URL(req.query.url);
  if (!ALLOWED.has(u.hostname) || u.protocol !== "https:") return res.sendStatus(400);
  res.send(Buffer.from(await (await fetch(u)).arrayBuffer()));
});
