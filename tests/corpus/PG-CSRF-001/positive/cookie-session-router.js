// corpus: expect=PG-CSRF-001
// Note: sameSite lax blocks cross-site POST, but same-site attackers (a sibling subdomain) remain.
const router = require("express").Router();
const cookieSession = require("cookie-session");
router.use(cookieSession({ keys: [process.env.K], httpOnly: true, secure: true, sameSite: "lax" }));

router.post("/settings", (req, res) => res.json({ ok: true }));
module.exports = router;
