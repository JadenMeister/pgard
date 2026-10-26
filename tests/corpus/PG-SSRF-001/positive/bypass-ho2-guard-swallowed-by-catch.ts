// corpus: expect=PG-SSRF-001
const ALLOWED = new Set(["api.example.com"]);
export async function hook(req: any, res: any) {
  const u = new URL(req.body.callback);
  try {
    if (!ALLOWED.has(u.hostname) || u.protocol !== "https:") throw new Error("blocked");
  } catch (e) {
    console.error(e);
  }
  await fetch(u, { method: "POST" });
  res.end();
}
