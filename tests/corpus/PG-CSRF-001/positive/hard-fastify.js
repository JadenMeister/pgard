// corpus: expect=PG-CSRF-001; known=miss:PG-CSRF-001:only express-session, cookie-session and cookie-parser count as a cookie session, so @fastify/session and @fastify/cookie do not
const fastify = require("fastify")();
fastify.register(require("@fastify/cookie"));
fastify.register(require("@fastify/session"), { secret: process.env.S, cookie: { secure: true } });

fastify.post("/transfer", async (request, reply) => {
  return { ok: true };
});
