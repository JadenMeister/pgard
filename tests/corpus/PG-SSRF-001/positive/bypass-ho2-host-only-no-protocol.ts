// corpus: expect=PG-SSRF-001
import { Hono } from "hono";
const app = new Hono();
app.get("/p", async (c) => {
  const u = new URL(c.req.query("u") ?? "");
  if (u.hostname !== "files.example.com") return c.text("no", 400);
  return fetch(u);
});
