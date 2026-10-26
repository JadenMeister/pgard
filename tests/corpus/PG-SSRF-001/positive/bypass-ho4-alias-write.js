// corpus: expect=PG-SSRF-001
const express = require("express");
const router = express.Router();
router.post("/preview", async (req, res) => {
  const target = new URL(req.body.link);
  if (target.hostname !== "img.example.com" || target.protocol !== "https:") return res.status(400).end();
  const view = target;
  view.hostname = req.body.mirror;
  const upstream = await fetch(target);
  res.type("png").send(Buffer.from(await upstream.arrayBuffer()));
});
module.exports = router;
