// corpus: expect=PG-BRUTE-001
const router = require("express").Router();

router.post("/signin", async (req, res) => {
  res.json({ token: await signIn(req.body) });
});
module.exports = router;
