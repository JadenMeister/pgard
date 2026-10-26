// corpus: expect=PG-COOKIE-001
// Koa defaults httpOnly to true, but secure and sameSite are still unset.
module.exports = async (ctx) => {
  ctx.cookies.set("session", issue(ctx), { maxAge: 3600000 });
  ctx.status = 204;
};
