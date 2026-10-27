// corpus: expect=PG-CSRF-001,PG-COOKIE-001; known=miss:PG-CSRF-001:koa-session is not recognised as a cookie session; known=miss:PG-COOKIE-001:koa-session default cookie options are not judged
const Koa = require("koa");
const Router = require("@koa/router");
const session = require("koa-session");
const app = new Koa();
const router = new Router();
app.use(session({ key: "koa.sess" }, app));
router.post("/transfer", (ctx) => {
  ctx.body = { ok: true };
});
app.use(router.routes());
