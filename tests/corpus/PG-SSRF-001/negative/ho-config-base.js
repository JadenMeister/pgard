// corpus: expect=none
const API_BASE = process.env.UPSTREAM_URL;

app.get("/health", async (req, res) => {
  const upstream = await fetch(`${API_BASE}/health`);
  res.json({ ok: upstream.ok });
});
