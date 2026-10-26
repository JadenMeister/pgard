// corpus: expect=PG-BRUTE-001
const Router = require("@koa/router");
const router = new Router();

router.post("/login", async (ctx) => {
  ctx.body = { token: await signIn(ctx.request.body) };
});
module.exports = router;
